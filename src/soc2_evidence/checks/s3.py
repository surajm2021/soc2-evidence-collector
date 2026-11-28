from botocore.exceptions import ClientError

from soc2_evidence.models import CheckResult, Context, Status

CHECK_ID = "s3-encryption-public-access"
CONTROLS = ["CC6.1", "CC6.7"]

PAB_FLAGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


def _error_code(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")


def _account_pab(session) -> bool:
    """True when account-level Block Public Access has all four settings on."""
    account_id = session.client("sts").get_caller_identity()["Account"]
    try:
        cfg = session.client("s3control").get_public_access_block(AccountId=account_id)
    except ClientError as exc:
        if _error_code(exc) == "NoSuchPublicAccessBlockConfiguration":
            return False
        raise
    return all(cfg["PublicAccessBlockConfiguration"].get(f) for f in PAB_FLAGS)


def _bucket_encryption(s3, bucket: str) -> str | None:
    try:
        rules = s3.get_bucket_encryption(Bucket=bucket)["ServerSideEncryptionConfiguration"][
            "Rules"
        ]
    except ClientError as exc:
        if _error_code(exc) == "ServerSideEncryptionConfigurationNotFoundError":
            return None
        raise
    default = rules[0].get("ApplyServerSideEncryptionByDefault", {})
    return default.get("SSEAlgorithm")


def _bucket_pab(s3, bucket: str) -> bool:
    try:
        cfg = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
    except ClientError as exc:
        if _error_code(exc) == "NoSuchPublicAccessBlockConfiguration":
            return False
        raise
    return all(cfg.get(f) for f in PAB_FLAGS)


def buckets_encrypted_and_private(session, ctx: Context | None = None) -> CheckResult:
    """Every bucket has default encryption and is covered by Block Public Access.

    Block Public Access counts if it is enabled on the bucket or for the whole
    account.
    """
    s3 = session.client("s3")
    account_pab = _account_pab(session)
    buckets, failing = [], []
    for bucket in s3.list_buckets()["Buckets"]:
        name = bucket["Name"]
        record = {
            "bucket": name,
            "encryption": _bucket_encryption(s3, name),
            "public_access_blocked": account_pab or _bucket_pab(s3, name),
        }
        buckets.append(record)
        if not record["encryption"] or not record["public_access_blocked"]:
            failing.append(name)

    if failing:
        summary = f"{len(failing)} of {len(buckets)} buckets lack encryption or Block Public Access"
    else:
        summary = f"all {len(buckets)} buckets are encrypted and block public access"
    return CheckResult(
        check=CHECK_ID,
        controls=CONTROLS,
        status=Status.FAIL if failing else Status.PASS,
        summary=summary,
        failing_resources=sorted(failing),
        evidence={"account_public_access_block": account_pab, "buckets": buckets},
    )
