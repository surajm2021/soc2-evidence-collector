import json
from datetime import UTC, datetime

from soc2_evidence.bundle import write_bundle
from soc2_evidence.cli import main
from soc2_evidence.models import CheckResult, Status

NOW = datetime(2026, 11, 24, 9, 30, tzinfo=UTC)
RESULTS = [
    CheckResult(
        "iam-console-mfa", ["CC6.1"], Status.FAIL, "1 of 2 console users have no MFA", ["bob"]
    ),
    CheckResult("cloudtrail-enabled", ["CC7.2"], Status.PASS, "multi-region trail logging: org"),
]


def test_bundle_layout(tmp_path):
    bundle = write_bundle(RESULTS, tmp_path, "123456789012", "eu-west-1", now=NOW)

    assert bundle == tmp_path / "123456789012" / "2026-11-24"
    assert sorted(p.name for p in bundle.iterdir()) == [
        "cloudtrail-enabled.json",
        "iam-console-mfa.json",
        "metadata.json",
        "summary.md",
    ]
    check = json.loads((bundle / "iam-console-mfa.json").read_text())
    assert check["collected_at"] == "2026-11-24T09:30:00+00:00"
    assert check["failing_resources"] == ["bob"]
    meta = json.loads((bundle / "metadata.json").read_text())
    assert meta["checks"] == ["iam-console-mfa", "cloudtrail-enabled"]


def test_summary_lists_failures_and_criteria(tmp_path):
    bundle = write_bundle(RESULTS, tmp_path, "123456789012", "eu-west-1", now=NOW)
    summary = (bundle / "summary.md").read_text()

    assert "1 of 2 checks passed" in summary
    assert "- `iam-console-mfa`: bob" in summary
    assert "- **CC7.2**: `cloudtrail-enabled`" in summary


def test_collect_command_writes_bundle(session, tmp_path, capsys):
    code = main(["collect", "--out", str(tmp_path), "--check", "iam-console-mfa"])

    out = capsys.readouterr().out
    assert code == 0
    assert "evidence written to" in out
    [account_dir] = list(tmp_path.iterdir())
    [day_dir] = list(account_dir.iterdir())
    assert (day_dir / "summary.md").exists()
