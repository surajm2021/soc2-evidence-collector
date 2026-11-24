# soc2-evidence-collector

Collect SOC 2 audit evidence from AWS accounts.

Each check calls read-only AWS APIs, decides PASS or FAIL, and keeps the raw data it looked at so
an auditor can see exactly what was checked and when.

## Checks

| Check | SOC 2 criteria | Passes when |
|-------|----------------|-------------|
| `iam-console-mfa` | CC6.1 | every IAM user with a console password has an MFA device |
| `cloudtrail-enabled` | CC7.2 | at least one multi-region trail is logging with log file validation enabled |

The criteria mappings are common starting points, not an audit opinion. Confirm them with your
auditor.

## Usage

```bash
pip install -e .
soc2-evidence run --profile audit
soc2-evidence run --json > results.json
```

The command exits with status 1 when any check fails, so it can gate a pipeline.

## Development

```bash
pip install -e '.[dev]'
pytest
```

Tests run against [moto](https://github.com/getmoto/moto); no AWS account is needed.

## License

MIT
