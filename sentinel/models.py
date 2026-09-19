from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone


def get_utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def color(self) -> str:
        match self:
            case Severity.CRITICAL:
                return "bold red"
            case Severity.HIGH:
                return "bold orange3"
            case Severity.MEDIUM:
                return "bold yellow"
            case Severity.LOW:
                return "bold cyan"
            case Severity.INFO:
                return "bold blue"

    @property
    def badge(self) -> str:
        match self:
            case Severity.CRITICAL:
                return "[bold white on red] CRITICAL [/]"
            case Severity.HIGH:
                return "[bold white on dark_orange] HIGH [/]"
            case Severity.MEDIUM:
                return "[bold black on yellow] MEDIUM [/]"
            case Severity.LOW:
                return "[bold black on cyan] LOW [/]"
            case Severity.INFO:
                return "[bold white on blue] INFO [/]"


class VulnCategory(str, Enum):
    PATH_TRAVERSAL = "Path Traversal & Arbitrary File Access"
    COMMAND_INJECTION = "Command & Shell Injection"
    SSRF = "Server-Side Request Forgery (SSRF)"
    SECRET_LEAK = "Hardcoded Secret & Credential Leakage"
    OVERPRIVILEGED = "Overprivileged Tool & Parameter Definition"
    UNICODE_SMUGGLING = "Invisible Unicode Tag & ASCII Smuggling"
    TOOL_SHADOWING = "Tool Shadowing & Description Hijacking"
    MISSING_VALIDATION = "Missing Parameter Boundary Validation"


class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    category: VulnCategory
    tool_name: str
    parameter: Optional[str] = None
    description: str
    proof_of_concept: Optional[str] = None
    remediation: str
    cwe_id: Optional[str] = "CWE-20"
    payload: Optional[str] = None
    response_snippet: Optional[str] = None
    timestamp: datetime = Field(default_factory=get_utc_now)


class ToolDefinition(BaseModel):
    name: str
    description: Optional[str] = ""
    input_schema: Dict[str, Any] = Field(default_factory=dict)


class ScanSummary(BaseModel):
    target: str
    total_tools: int = 0
    scanned_tools: List[str] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    start_time: datetime = Field(default_factory=get_utc_now)
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    @property
    def security_score(self) -> int:
        """Calculates a 0-100 security health score (100 = spotless)."""
        deductions = (
            self.critical_count * 30
            + self.high_count * 15
            + self.medium_count * 7
            + self.low_count * 2
        )
        return max(0, 100 - deductions)
