from soc2_evidence.models import CheckResult, Status

CHECK_ID = "cloudtrail-enabled"
CONTROLS = ["CC7.2"]


def multi_region_trail_logging(session) -> CheckResult:
    """At least one multi-region trail is logging with log file validation on."""
    ct = session.client("cloudtrail")
    trails = ct.describe_trails(includeShadowTrails=False)["trailList"]
    evidence, good, problems = [], [], []
    for trail in trails:
        status = ct.get_trail_status(Name=trail["TrailARN"])
        record = {
            "name": trail["Name"],
            "multi_region": trail.get("IsMultiRegionTrail", False),
            "log_file_validation": trail.get("LogFileValidationEnabled", False),
            "is_logging": status.get("IsLogging", False),
            "s3_bucket": trail.get("S3BucketName"),
        }
        evidence.append(record)
        missing = [
            k for k in ("multi_region", "log_file_validation", "is_logging") if not record[k]
        ]
        if missing:
            problems.append(f"{trail['Name']} ({', '.join(missing)} off)")
        else:
            good.append(trail["Name"])

    if good:
        status, summary = Status.PASS, f"multi-region trail logging: {', '.join(sorted(good))}"
    elif trails:
        status, summary = Status.FAIL, "no trail meets the bar: " + "; ".join(problems)
    else:
        status, summary = Status.FAIL, "no CloudTrail trails configured"
    return CheckResult(
        check=CHECK_ID,
        controls=CONTROLS,
        status=status,
        summary=summary,
        failing_resources=[] if good else [t["name"] for t in evidence],
        evidence={"trails": evidence},
    )
