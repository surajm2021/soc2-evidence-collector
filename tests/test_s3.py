from soc2_evidence.checks.s3 import buckets_encrypted_and_private
from soc2_evidence.models import Status

ALL_ON = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


def _bucket(s3, name, encrypted=True, pab=True):
    s3.create_bucket(Bucket=name)
    if encrypted:
        s3.put_bucket_encryption(
            Bucket=name,
            ServerSideEncryptionConfiguration={
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]
            },
        )
    if pab:
        s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration=ALL_ON)


def test_passes_when_buckets_are_encrypted_and_blocked(session):
    s3 = session.client("s3")
    _bucket(s3, "app-data")
    _bucket(s3, "app-logs")

    result = buckets_encrypted_and_private(session)

    assert result.status is Status.PASS
    assert {b["encryption"] for b in result.evidence["buckets"]} == {"aws:kms"}


def test_fails_for_bucket_without_public_access_block(session):
    s3 = session.client("s3")
    _bucket(s3, "app-data")
    _bucket(s3, "marketing-site", pab=False)

    result = buckets_encrypted_and_private(session)

    assert result.status is Status.FAIL
    assert result.failing_resources == ["marketing-site"]


def test_account_level_block_public_access_covers_buckets(session):
    s3 = session.client("s3")
    _bucket(s3, "app-data", pab=False)
    account_id = session.client("sts").get_caller_identity()["Account"]
    session.client("s3control").put_public_access_block(
        AccountId=account_id, PublicAccessBlockConfiguration=ALL_ON
    )

    result = buckets_encrypted_and_private(session)

    assert result.evidence["account_public_access_block"] is True
    assert result.status is Status.PASS


def test_partial_block_public_access_is_not_enough(session):
    s3 = session.client("s3")
    _bucket(s3, "half-open", pab=False)
    s3.put_public_access_block(
        Bucket="half-open",
        PublicAccessBlockConfiguration={**ALL_ON, "RestrictPublicBuckets": False},
    )

    assert buckets_encrypted_and_private(session).failing_resources == ["half-open"]
