from soc2_evidence.models import CheckResult, Status

CHECK_ID = "iam-console-mfa"
CONTROLS = ["CC6.1"]


def _has_console_password(iam, user_name: str) -> bool:
    try:
        iam.get_login_profile(UserName=user_name)
        return True
    except iam.exceptions.NoSuchEntityException:
        return False


def console_users_have_mfa(session) -> CheckResult:
    """Every IAM user that can sign in to the console must have an MFA device."""
    iam = session.client("iam")
    console_users, without_mfa = [], []
    for page in iam.get_paginator("list_users").paginate():
        for user in page["Users"]:
            name = user["UserName"]
            if not _has_console_password(iam, name):
                continue
            console_users.append(name)
            if not iam.list_mfa_devices(UserName=name)["MFADevices"]:
                without_mfa.append(name)

    status = Status.FAIL if without_mfa else Status.PASS
    summary = (
        f"{len(without_mfa)} of {len(console_users)} console users have no MFA device"
        if without_mfa
        else f"all {len(console_users)} console users have an MFA device"
    )
    return CheckResult(
        check=CHECK_ID,
        controls=CONTROLS,
        status=status,
        summary=summary,
        failing_resources=sorted(without_mfa),
        evidence={"console_users": sorted(console_users)},
    )
