"""Command line entry point: `soc2-evidence run`."""

import argparse
import json
import sys

import boto3

from soc2_evidence import __version__
from soc2_evidence.checks import ALL_CHECKS
from soc2_evidence.models import CheckResult, Status


def run_checks(session, names: list[str]) -> list[CheckResult]:
    results = []
    for name in names:
        try:
            results.append(ALL_CHECKS[name](session))
        except Exception as exc:  # noqa: BLE001 - one broken check must not hide the others
            results.append(
                CheckResult(
                    check=name,
                    controls=[],
                    status=Status.ERROR,
                    summary=f"{type(exc).__name__}: {exc}",
                )
            )
    return results


def render_table(results: list[CheckResult]) -> str:
    lines = [f"{r.status:<6} {r.check:<20} {','.join(r.controls):<8} {r.summary}" for r in results]
    failed = sum(r.status != Status.PASS for r in results)
    lines += ["", f"{len(results) - failed} passed, {failed} need attention"]
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="soc2-evidence", description=__doc__)
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="run checks and print the results")
    run.add_argument("--profile", help="AWS named profile")
    run.add_argument("--region", default="us-east-1", help="region for regional APIs")
    run.add_argument("--check", action="append", choices=sorted(ALL_CHECKS))
    run.add_argument("--json", action="store_true", help="print raw results as JSON")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    results = run_checks(session, args.check or sorted(ALL_CHECKS))
    if args.json:
        print(json.dumps([r.to_dict() for r in results], indent=2, default=str))
    else:
        print(render_table(results))
    return 0 if all(r.status == Status.PASS for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
