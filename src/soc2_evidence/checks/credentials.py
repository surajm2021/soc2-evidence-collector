"""Checks based on the IAM credential report (root account and access key age)."""

import csv
import io
import time
from datetime import UTC, datetime

from soc2_evidence.models import CheckResult, Context, Status

ROOT_CHECK_ID = "root-account"
KEY_AGE_CHECK_ID = "access-key-age"
CONTROLS = ["CC6.1"]
ROOT_USER = "<root_account>"


def fetch_report(iam, attempts: int = 10, sleep=time.sleep) -> list[dict]:
    """Generate (if needed) and download the credential report as a list of rows."""
    for _ in range(attempts):
        state = iam.generate_credential_report()["State"]
        if state == "COMPLETE":
            break
        sleep(2)
    else:
        raise TimeoutError("credential report was not ready in time")
    content = iam.get_credential_report()["Content"]
    if isinstance(content, bytes):
        content = content.decode("utf-8")
    return parse_report(content)


def parse_report(content: str) -> list[dict]:
    return list(csv.DictReader(io.StringIO(content)))


def _true(value: str | None) -> bool:
    return (value or "").strip().lower() == "true"


def _timestamp(value: str | None) -> datetime | None:
    if not value or value in ("N/A", "not_supported", "no_information"):
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def evaluate_root(rows: list[dict]) -> CheckResult:
    """The root user must have MFA and no active access keys."""
    root = next((r for r in rows if r.get("user") == ROOT_USER), None)
    if root is None:
        return CheckResult(ROOT_CHECK_ID, CONTROLS, Status.FAIL, "root account missing from report")
    evidence = {
        "mfa_active": _true(root.get("mfa_active")),
        "access_key_1_active": _true(root.get("access_key_1_active")),
        "access_key_2_active": _true(root.get("access_key_2_active")),
        "password_last_used": root.get("password_last_used"),
    }
    problems = []
    if not evidence["mfa_active"]:
        problems.append("no MFA")
    if evidence["access_key_1_active"] or evidence["access_key_2_active"]:
        problems.append("active access keys")
    if problems:
        return CheckResult(
            ROOT_CHECK_ID,
            CONTROLS,
            Status.FAIL,
            "root account has " + " and ".join(problems),
            failing_resources=[ROOT_USER],
            evidence=evidence,
        )
    return CheckResult(
        ROOT_CHECK_ID, CONTROLS, Status.PASS, "root has MFA and no access keys", evidence=evidence
    )


def evaluate_key_age(rows: list[dict], max_age_days: int, now: datetime) -> CheckResult:
    """Every active access key must have been rotated within max_age_days."""
    stale, active = [], 0
    for row in rows:
        if row.get("user") == ROOT_USER:
            continue  # covered by root-account
        for slot in ("1", "2"):
            if not _true(row.get(f"access_key_{slot}_active")):
                continue
            active += 1
            rotated = _timestamp(row.get(f"access_key_{slot}_last_rotated"))
            age = (now - rotated).days if rotated else None
            if age is None or age > max_age_days:
                stale.append(
                    {
                        "user": row["user"],
                        "key": slot,
                        "age_days": age,
                        "last_used": row.get(f"access_key_{slot}_last_used_date"),
                    }
                )
    if stale:
        summary = f"{len(stale)} of {active} active access keys are older than {max_age_days} days"
    else:
        summary = f"all {active} active access keys rotated within {max_age_days} days"
    return CheckResult(
        KEY_AGE_CHECK_ID,
        CONTROLS,
        Status.FAIL if stale else Status.PASS,
        summary,
        failing_resources=sorted({f"{s['user']} (key {s['key']})" for s in stale}),
        evidence={"max_age_days": max_age_days, "active_keys": active, "stale_keys": stale},
    )


def root_account_secured(session, ctx: Context | None = None) -> CheckResult:
    return evaluate_root(fetch_report(session.client("iam")))


def access_keys_rotated(session, ctx: Context | None = None) -> CheckResult:
    ctx = ctx or Context()
    rows = fetch_report(session.client("iam"))
    return evaluate_key_age(rows, ctx.max_key_age_days, ctx.now or datetime.now(UTC))
