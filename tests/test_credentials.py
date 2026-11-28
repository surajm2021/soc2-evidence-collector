from datetime import UTC, datetime, timedelta

from soc2_evidence.checks.credentials import (
    access_keys_rotated,
    evaluate_key_age,
    evaluate_root,
    fetch_report,
    parse_report,
)
from soc2_evidence.models import Context, Status

HEADER = (
    "user,arn,user_creation_time,password_enabled,password_last_used,mfa_active,"
    "access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,"
    "access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date"
)
NOW = datetime(2026, 11, 24, tzinfo=UTC)


def report(*rows):
    return parse_report("\n".join([HEADER, *rows]) + "\n")


ROOT_PREFIX = (
    "<root_account>,arn:aws:iam::123456789012:root,2020-01-01T00:00:00+00:00,"
    "not_supported,2026-10-01T00:00:00+00:00"
)
ROOT_OK = ROOT_PREFIX + ",true,false,N/A,N/A,false,N/A,N/A"
ROOT_BAD = (
    ROOT_PREFIX + ",false,true,2021-01-01T00:00:00+00:00,2026-11-01T00:00:00+00:00,false,N/A,N/A"
)


def user(name, key1=None, key2=None):
    def slot(rotated):
        if rotated is None:
            return "false,N/A,N/A"
        return f"true,{rotated.isoformat()},2026-11-20T00:00:00+00:00"

    return (
        f"{name},arn:aws:iam::123456789012:user/{name},2024-01-01T00:00:00+00:00,false,N/A,false,"
        f"{slot(key1)},{slot(key2)}"
    )


def test_root_passes_with_mfa_and_no_keys():
    result = evaluate_root(report(ROOT_OK))

    assert result.status is Status.PASS
    assert result.evidence["mfa_active"] is True


def test_root_fails_without_mfa_or_with_keys():
    result = evaluate_root(report(ROOT_BAD))

    assert result.status is Status.FAIL
    assert result.summary == "root account has no MFA and active access keys"


def test_root_missing_from_report():
    assert evaluate_root(report(user("alice"))).status is Status.FAIL


def test_key_age_flags_old_keys_only():
    rows = report(
        ROOT_BAD,  # root keys are ignored here
        user("ci-deploy", key1=NOW - timedelta(days=200)),
        user("app", key1=NOW - timedelta(days=10), key2=NOW - timedelta(days=95)),
        user("no-keys"),
    )

    result = evaluate_key_age(rows, max_age_days=90, now=NOW)

    assert result.status is Status.FAIL
    assert result.summary == "2 of 3 active access keys are older than 90 days"
    assert result.failing_resources == ["app (key 2)", "ci-deploy (key 1)"]
    assert {s["age_days"] for s in result.evidence["stale_keys"]} == {200, 95}


def test_key_age_passes_when_rotated():
    rows = report(user("app", key1=NOW - timedelta(days=30)))

    assert evaluate_key_age(rows, max_age_days=90, now=NOW).status is Status.PASS


def test_fetch_report_waits_until_complete():
    class FakeIAM:
        def __init__(self):
            self.calls = 0

        def generate_credential_report(self):
            self.calls += 1
            return {"State": "COMPLETE" if self.calls >= 3 else "STARTED"}

        def get_credential_report(self):
            return {"Content": (HEADER + "\n" + ROOT_OK + "\n").encode()}

    iam = FakeIAM()
    rows = fetch_report(iam, sleep=lambda s: None)

    assert iam.calls == 3
    assert rows[0]["user"] == "<root_account>"


def test_access_key_age_against_moto(session):
    iam = session.client("iam")
    iam.create_user(UserName="ci-deploy")
    iam.create_access_key(UserName="ci-deploy")
    later = datetime.now(UTC) + timedelta(days=120)

    result = access_keys_rotated(session, Context(max_key_age_days=90, now=later))

    assert result.status is Status.FAIL
    assert result.failing_resources == ["ci-deploy (key 1)"]
