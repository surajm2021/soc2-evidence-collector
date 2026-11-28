from soc2_evidence.checks import cloudtrail, iam, s3

ALL_CHECKS = {
    iam.CHECK_ID: iam.console_users_have_mfa,
    cloudtrail.CHECK_ID: cloudtrail.multi_region_trail_logging,
    s3.CHECK_ID: s3.buckets_encrypted_and_private,
}

__all__ = ["ALL_CHECKS"]
