from dataclasses import dataclass, field
from datetime import datetime
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


@dataclass(frozen=True)
class Context:
    """Options shared by every check."""

    regions: tuple[str, ...] = ("us-east-1",)
    max_key_age_days: int = 90
    now: datetime | None = None
