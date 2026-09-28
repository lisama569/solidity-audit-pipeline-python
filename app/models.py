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
    BASELINE_NOT_FOUND = "BASELINE_NOT_FOUND"    # 基线任务不存在
    BASELINE_NOT_READY = "BASELINE_NOT_READY"    # 基线尚未审计完成
    BASELINE_MISMATCH = "BASELINE_MISMATCH"      # 基线与当前提交对不上
    NEW_VERSION_NOT_READY = "NEW_VERSION_NOT_READY"  # 新版本审计未完成/失败


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


class DeltaCategory(str, enum.Enum):
    """新版本相对基线的问题分类。"""

    NEW = "NEW"                    # 新版本多出的问题
    FIXED = "FIXED"                # 基线有、新版本已修复的问题
    PERSISTENT = "PERSISTENT"      # 两边都在、实质未变的问题
    SEVERITY_CHANGED = "SEVERITY_CHANGED"  # 同一问题，严重程度发生变化


@dataclass(frozen=True)
class SourceFile:
    """单个来源文件：逻辑路径 + 文本内容。"""

    path: str
    content: str


@dataclass(frozen=True)
class IssueRef:
    """单条规则视角下的问题稳定身份（与行号/命名/注释无关，只依赖问题实质）。

    - rule_id：哪条规则识别出的问题（规则是身份的一部分，一条 Finding 可含多条）；
    - issue_key：规则层从问题代码结构计算的稳定标识，代码整体挪动、纯重命名、
      纯注释变化都不会改变它，问题实质修复或新增时才会变化；
    - severity：该规则对该问题给出的严重程度（合并后 Finding 的严重度取最高）。
    """

    rule_id: str
    issue_key: str
    severity: Severity


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
    issues: tuple[IssueRef, ...] = field(default_factory=tuple)


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


@dataclass(frozen=True)
class FindingSide:
    """一条差异在某一侧（基线/新版本）的具体形态。"""

    finding_id: str
    severity: Severity
    file: str
    line: int
    contract: str
    function: str
    message: str


@dataclass(frozen=True)
class FindingDelta:
    """单条问题在新版本相对基线下的差异。"""

    delta_id: str                      # 该对比内稳定的差异编号
    category: DeltaCategory
    rule_id: str                       # 以哪条规则的视角匹配
    issue_key: str                     # 问题稳定身份
    baseline_severity: Severity | None
    current_severity: Severity | None
    baseline: FindingSide | None = None
    current: FindingSide | None = None


@dataclass(frozen=True)
class ComparisonReport:
    """新版本相对基线的完整对比结论。"""

    baseline_task_id: str                  # 基线任务
    current_task_id: str                   # 新版本任务
    baseline_fingerprint: str
    current_fingerprint: str
    baseline_report_hash: str
    current_report_hash: str
    deltas: tuple[FindingDelta, ...]       # 已按稳定顺序排序
    counts: dict[str, int]                 # 四类计数
    comparison_hash: str                   # 对比结论内容哈希


@dataclass
class CompareRecord:
    """版本对比任务的生命周期记录（可持久化）。"""

    compare_id: str
    current_fingerprint: str
    baseline_task_id: str
    current_task_id: str
    status: TaskStatus
    attempts: int = 0
    error_code: str | None = None
    error_detail: str | None = None
    result: ComparisonReport | None = None
    created_at: float = 0.0
    updated_at: float = 0.0
