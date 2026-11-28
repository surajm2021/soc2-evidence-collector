"""Write check results as a dated evidence bundle an auditor can review."""

import json
from datetime import UTC, datetime
from pathlib import Path

from soc2_evidence import __version__
from soc2_evidence.models import CheckResult, Status


def write_bundle(
    results: list[CheckResult],
    out_dir: str | Path,
    account_id: str,
    region: str,
    now: datetime | None = None,
) -> Path:
    """Create <out_dir>/<account>/<YYYY-MM-DD>/ with one JSON file per check.

    Returns the bundle directory. Re-running on the same day overwrites that
    day's bundle, so the latest collection is always the one on disk.
    """
    now = now or datetime.now(UTC)
    bundle = Path(out_dir) / account_id / now.strftime("%Y-%m-%d")
    bundle.mkdir(parents=True, exist_ok=True)

    for result in results:
        doc = {"collected_at": now.isoformat(timespec="seconds"), **result.to_dict()}
        (bundle / f"{result.check}.json").write_text(json.dumps(doc, indent=2, default=str) + "\n")

    metadata = {
        "account_id": account_id,
        "region": region,
        "collected_at": now.isoformat(timespec="seconds"),
        "tool": "soc2-evidence-collector",
        "tool_version": __version__,
        "checks": [r.check for r in results],
    }
    (bundle / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    (bundle / "summary.md").write_text(render_summary(results, account_id, now))
    return bundle


def render_summary(results: list[CheckResult], account_id: str, now: datetime) -> str:
    passed = sum(r.status == Status.PASS for r in results)
    lines = [
        f"# SOC 2 evidence: account {account_id}",
        "",
        f"Collected {now.strftime('%Y-%m-%d %H:%M UTC')}: "
        f"{passed} of {len(results)} checks passed.",
        "",
        "| Status | Check | Criteria | Result |",
        "|--------|-------|----------|--------|",
    ]
    for r in results:
        lines.append(f"| {r.status} | `{r.check}` | {', '.join(r.controls)} | {r.summary} |")

    failing = [r for r in results if r.failing_resources]
    if failing:
        lines += ["", "## Resources needing attention", ""]
        for r in failing:
            lines.append(f"- `{r.check}`: {', '.join(r.failing_resources)}")

    by_control: dict[str, list[str]] = {}
    for r in results:
        for control in r.controls:
            by_control.setdefault(control, []).append(r.check)
    lines += ["", "## By criterion", ""]
    for control in sorted(by_control):
        lines.append(f"- **{control}**: {', '.join(f'`{c}`' for c in by_control[control])}")
    return "\n".join(lines) + "\n"
