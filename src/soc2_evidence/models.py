from dataclasses import dataclass, field
from enum import StrEnum


class Status(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"


@dataclass
class CheckResult:
    """Outcome of one evidence check, plus the raw data an auditor can review."""

    check: str
    controls: list[str]
    status: Status
    summary: str
    failing_resources: list[str] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "check": self.check,
            "controls": self.controls,
            "status": str(self.status),
            "summary": self.summary,
            "failing_resources": self.failing_resources,
            "evidence": self.evidence,
        }
