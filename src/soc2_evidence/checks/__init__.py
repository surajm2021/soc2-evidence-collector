from soc2_evidence.checks import cloudtrail, iam

ALL_CHECKS = {
    iam.CHECK_ID: iam.console_users_have_mfa,
    cloudtrail.CHECK_ID: cloudtrail.multi_region_trail_logging,
}

__all__ = ["ALL_CHECKS"]
