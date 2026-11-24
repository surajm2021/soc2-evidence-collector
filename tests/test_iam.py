from soc2_evidence.checks.iam import console_users_have_mfa
from soc2_evidence.cli import main, run_checks
from soc2_evidence.models import Status


def _console_user(iam, name, mfa=False):
    iam.create_user(UserName=name)
    iam.create_login_profile(UserName=name, Password="Correct-Horse-9!")
    if mfa:
        serial = iam.create_virtual_mfa_device(VirtualMFADeviceName=name)["VirtualMFADevice"][
            "SerialNumber"
        ]
        iam.enable_mfa_device(
            UserName=name,
            SerialNumber=serial,
            AuthenticationCode1="123456",
            AuthenticationCode2="654321",
        )


def test_passes_when_every_console_user_has_mfa(session):
    iam = session.client("iam")
    _console_user(iam, "alice", mfa=True)
    iam.create_user(UserName="ci-bot")  # API-only user, no console password

    result = console_users_have_mfa(session)

    assert result.status is Status.PASS
    assert result.evidence["console_users"] == ["alice"]


def test_fails_and_lists_users_without_mfa(session):
    iam = session.client("iam")
    _console_user(iam, "alice", mfa=True)
    _console_user(iam, "bob")
    _console_user(iam, "carol")

    result = console_users_have_mfa(session)

    assert result.status is Status.FAIL
    assert result.failing_resources == ["bob", "carol"]
    assert result.summary == "2 of 3 console users have no MFA device"
    assert result.controls == ["CC6.1"]


def test_broken_check_is_reported_as_error(session, monkeypatch):
    from soc2_evidence import checks

    def boom(_session):
        raise RuntimeError("AccessDenied")

    monkeypatch.setitem(checks.ALL_CHECKS, "iam-console-mfa", boom)

    [result] = run_checks(session, ["iam-console-mfa"])

    assert result.status is Status.ERROR
    assert "AccessDenied" in result.summary


def test_cli_exit_code_reflects_failures(session, capsys):
    _console_user(session.client("iam"), "dave")

    code = main(["run", "--check", "iam-console-mfa"])

    assert code == 1
    assert "FAIL   iam-console-mfa" in capsys.readouterr().out
