# soc2-evidence-collector

[![ci](https://github.com/surajm2021/soc2-evidence-collector/actions/workflows/ci.yml/badge.svg)](https://github.com/surajm2021/soc2-evidence-collector/actions/workflows/ci.yml)

_Built and maintained with an AI coding agent (Claude, by Anthropic) under the direction of [@surajm2021](https://github.com/surajm2021)._

Collect SOC 2 audit evidence from AWS accounts.

Each check calls read-only AWS APIs, decides PASS or FAIL, and keeps the raw data it looked at so
an auditor can see exactly what was checked and when.

## Checks

| Check | SOC 2 criteria | Passes when |
|-------|----------------|-------------|
| `iam-console-mfa` | CC6.1 | every IAM user with a console password has an MFA device |
| `cloudtrail-enabled` | CC7.2 | at least one multi-region trail is logging with log file validation enabled |
| `s3-encryption-public-access` | CC6.1, CC6.7 | every bucket has default encryption and Block Public Access (bucket or account level) |

The criteria mappings are common starting points, not an audit opinion. Confirm them with your
auditor.

## Usage

```bash
pip install -e .
soc2-evidence run --profile audit
soc2-evidence run --json > results.json
```

`run` exits with status 1 when any check fails, so it can gate a pipeline.

### Evidence bundles

`collect` runs the same checks and writes a dated bundle per account:

```bash
soc2-evidence collect --profile audit --out evidence/
```

```
evidence/
  123456789012/
    2026-11-24/
      summary.md                 # pass/fail table, failing resources, checks per criterion
      metadata.json              # account, region, timestamp, tool version
      iam-console-mfa.json       # raw evidence for each check
      cloudtrail-enabled.json
      s3-encryption-public-access.json
```

Running it on a schedule (monthly or quarterly) gives auditors a dated trail of point-in-time
evidence. Add `--strict` to exit non-zero when a check fails.

## Development

```bash
pip install -e '.[dev]'
pytest
```

Tests run against [moto](https://github.com/getmoto/moto); no AWS account is needed.

## License

MIT
