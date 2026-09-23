"""审计流水线的核心数据模型（纯类型，无业务行为）。"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class TaskState(str, enum.Enum):
    """任务生命周期状态。

    合法流转:
        QUEUED -> RUNNING -> COMPLETED
        QUEUED -> CANCELLED
        RUNNING -> FAILED | TIMEOUT | CANCELLED
        FAILED | TIMEOUT -> QUEUED   (重试)
    COMPLETED / CANCELLED 为终态。
    """

    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    TIMEOUT = "TIMEOUT"


TERMINAL_STATES = frozenset({TaskState.COMPLETED, TaskState.CANCELLED})
RETRYABLE_STATES = frozenset({TaskState.FAILED, TaskState.TIMEOUT})


class Severity(str, enum.Enum):
    """漏洞严重程度，排序权重越大越严重。"""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass(frozen=True)
class SourceFile:
    """一份本地提交的源文件。"""

    path: str
    content: str


@dataclass(frozen=True)
class Location:
    """漏洞定位信息。"""

    file: str
    line: int
    column: int = 0
    contract: str = ""
    function: str = ""
    snippet: str = ""

    def sort_key(self) -> tuple:
        return (self.file, self.line, self.column, self.contract, self.function)

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "contract": self.contract,
            "function": self.function,
            "snippet": self.snippet,
        }


@dataclass
class Finding:
    """单条归一后的审计结论。

    - key:   由规则类别与定位派生的稳定去重键，跨运行一致；
    - id:    报告内序号（F-0001 ...），按确定性排序分配；
    - rule_ids: 命中该问题的全部规则（多条规则命中同一问题时合并）。
    """

    key: str
    rule_ids: list[str]
    category: str
    title: str
    severity: Severity
    description: str
    locations: list[Location]
    evidence: list[str] = field(default_factory=list)
    id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "key": self.key,
            "category": self.category,
            "title": self.title,
            "severity": self.severity.value,
            "rule_ids": list(self.rule_ids),
            "description": self.description,
            "locations": [loc.to_dict() for loc in self.locations],
            "evidence": list(self.evidence),
        }


@dataclass
class AuditReport:
    """一次审计的完整、可复现结论。"""

    content_hash: str
    findings: list[Finding]
    rules_evaluated: list[str]
    no_findings: bool
    conclusion: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "content_hash": self.content_hash,
            "conclusion": self.conclusion,
            "no_findings": self.no_findings,
            "finding_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "rules_evaluated": list(self.rules_evaluated),
        }


@dataclass
class Task:
    """一个审计任务及其持久化状态。"""

    id: str
    content_hash: str
    state: TaskState
    entry_point: str
    sources: dict[str, str]
    attempts: int = 0
    max_attempts: int = 3
    created_at: float = 0.0
    updated_at: float = 0.0
    started_at: float | None = None
    deadline: float | None = None
    report: AuditReport | None = None
    error: dict[str, Any] | None = None
    client_labels: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "content_hash": self.content_hash,
            "state": self.state.value,
            "entry_point": self.entry_point,
            "attempts": self.attempts,
            "max_attempts": self.max_attempts,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "started_at": self.started_at,
            "deadline": self.deadline,
            "report": self.report.to_dict() if self.report else None,
            "error": self.error,
            "client_labels": list(self.client_labels),
        }
