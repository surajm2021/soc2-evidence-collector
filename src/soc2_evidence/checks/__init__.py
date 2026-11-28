from soc2_evidence.checks import cloudtrail, credentials, iam, s3

ALL_CHECKS = {
    iam.CHECK_ID: iam.console_users_have_mfa,
    credentials.ROOT_CHECK_ID: credentials.root_account_secured,
    credentials.KEY_AGE_CHECK_ID: credentials.access_keys_rotated,
    cloudtrail.CHECK_ID: cloudtrail.multi_region_trail_logging,
    s3.CHECK_ID: s3.buckets_encrypted_and_private,
}

__all__ = ["ALL_CHECKS"]
