"""核心类型定义：提交、任务状态、审计结论。"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field


class ErrorCode(str, enum.Enum):
    """彼此可区分的失败原因。"""

    SOURCE_MISSING = "SOURCE_MISSING"            # 来源文件缺失
    IMPORT_UNRESOLVABLE = "IMPORT_UNRESOLVABLE"  # 导入无法解析
    INVALID_CONTENT = "INVALID_CONTENT"          # 内容非法（非 UTF-8 / 语法非法）
    TASK_TIMEOUT = "TASK_TIMEOUT"                # 任务超时
    TASK_CANCELLED = "TASK_CANCELLED"            # 任务被取消
    INTERNAL_ERROR = "INTERNAL_ERROR"            # 内部错误


class TaskStatus(str, enum.Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"        # 可重试的失败
    CANCELLED = "CANCELLED"
    TIMEOUT = "TIMEOUT"


TERMINAL_STATES = frozenset({TaskStatus.SUCCEEDED, TaskStatus.CANCELLED, TaskStatus.TIMEOUT})


class Severity(enum.IntEnum):
    """严重程度，数值越大越严重；排序稳定。"""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass(frozen=True)
class SourceFile:
    """单个来源文件：逻辑路径 + 文本内容。"""

    path: str
    content: str


@dataclass(frozen=True)
class Finding:
    """归一后的单条审计结论。"""

    finding_id: str          # 稳定编号，由规则+位置+内容指纹派生
    rule_ids: tuple[str, ...]  # 命中该问题的全部规则（已合并去重、排序）
    severity: Severity
    file: str
    line: int
    contract: str
    function: str
    message: str


@dataclass(frozen=True)
class AuditReport:
    """一次审计的最终结论。"""

    fingerprint: str                 # 输入指纹（内容寻址）
    findings: tuple[Finding, ...]    # 已按严重程度与编号稳定排序
    clean: bool                      # 未命中任何规则时为 True
    report_hash: str                 # 结论内容哈希，用于可复现性校验


@dataclass
class TaskRecord:
    """任务生命周期记录（可持久化）。"""

    task_id: str
    fingerprint: str
    status: TaskStatus
    attempts: int = 0
    error_code: str | None = None
    error_detail: str | None = None
    report: AuditReport | None = None
    created_at: float = 0.0
    updated_at: float = 0.0
