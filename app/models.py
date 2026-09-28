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
    BASELINE_NOT_FOUND = "BASELINE_NOT_FOUND"    # 指定的基线任务不存在
    BASELINE_NOT_READY = "BASELINE_NOT_READY"    # 基线尚未审计完成
    BASELINE_UNRELATED = "BASELINE_UNRELATED"    # 基线与当前提交对不上


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
    signature: str = ""      # 跨版本稳定匹配签名（与位置/命名无关，实质变化才变）


class DiffCategory(str, enum.Enum):
    """新版本相对基线的单条问题分类。"""

    NEW = "NEW"                    # 新版本多出来的问题
    FIXED = "FIXED"                # 基线有、新版本已消失的问题
    PERSISTING = "PERSISTING"      # 两边都在且实质未变（严重程度也相同）
    SEVERITY_CHANGED = "SEVERITY_CHANGED"  # 两边都在，但严重程度发生变化


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
    kind: str = "audit"          # audit | diff：区分单版本审计与版本对比
    attempts: int = 0
    error_code: str | None = None
    error_detail: str | None = None
    report: AuditReport | None = None
    baseline_task_id: str | None = None   # diff 任务：基线审计任务 id
    baseline_fingerprint: str | None = None  # diff 任务：基线输入指纹
    diff: "DiffReport | None" = None      # diff 任务：对比结论
    created_at: float = 0.0
    updated_at: float = 0.0


@dataclass(frozen=True)
class DiffEntry:
    """一条问题的跨版本对比结果。"""

    category: DiffCategory
    signature: str
    rule_ids: tuple[str, ...]
    baseline_finding: Finding | None   # FIXED 时只有基线侧
    current_finding: Finding | None    # NEW 时只有新版本侧
    baseline_severity: Severity | None
    current_severity: Severity | None


@dataclass(frozen=True)
class DiffReport:
    """一次版本对比的最终结论（相对某份基线）。"""

    diff_id: str                       # 由 (新版本指纹, 基线指纹) 内容寻址
    current_fingerprint: str           # 新版本输入指纹
    baseline_fingerprint: str          # 基线输入指纹
    baseline_task_id: str              # 对比所依据的基线任务
    current_report_hash: str
    baseline_report_hash: str
    entries: tuple[DiffEntry, ...]     # 已稳定排序
    counts: dict[str, int]             # 各分类条数（含 total）
    diff_hash: str                     # 对比结论内容哈希，用于可复现性校验
