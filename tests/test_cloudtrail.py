from soc2_evidence.checks.cloudtrail import multi_region_trail_logging
from soc2_evidence.models import Status


def _trail(session, name, multi_region=True, validation=True, logging=True):
    session.client("s3").create_bucket(Bucket=f"{name}-logs")
    ct = session.client("cloudtrail")
    ct.create_trail(
        Name=name,
        S3BucketName=f"{name}-logs",
        IsMultiRegionTrail=multi_region,
        EnableLogFileValidation=validation,
    )
    if logging:
        ct.start_logging(Name=name)


def test_passes_with_a_logging_multi_region_trail(session):
    _trail(session, "org-trail")

    result = multi_region_trail_logging(session)

    assert result.status is Status.PASS
    assert result.evidence["trails"][0]["is_logging"] is True


def test_fails_when_validation_is_off_or_trail_stopped(session):
    _trail(session, "no-validation", validation=False)
    _trail(session, "stopped", logging=False)

    result = multi_region_trail_logging(session)

    assert result.status is Status.FAIL
    assert "no-validation (log_file_validation off)" in result.summary
    assert "stopped (is_logging off)" in result.summary
    assert sorted(result.failing_resources) == ["no-validation", "stopped"]


def test_fails_without_trails(session):
    result = multi_region_trail_logging(session)

    assert result.status is Status.FAIL
    assert result.summary == "no CloudTrail trails configured"


def test_single_region_trail_does_not_count(session):
    _trail(session, "regional", multi_region=False)

    assert multi_region_trail_logging(session).status is Status.FAIL
