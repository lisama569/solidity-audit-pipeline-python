"""审计流水线中所有可区分的失败原因。

每一种失败都对应一个稳定的错误码，调用方可以据此区分
"来源缺失 / 导入无法解析 / 内容非法" 等不同情形，服务端绝不会静默跳过。
"""

from __future__ import annotations


class AuditError(Exception):
    """所有审计流水线错误的基类，携带稳定的机器可读错误码。"""

    code: str = "AUDIT_ERROR"

    def __init__(self, message: str, *, details: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details: dict = details or {}

    def to_dict(self) -> dict:
        return {"code": self.code, "message": self.message, "details": self.details}


class SourceMissingError(AuditError):
    """提交的来源中缺少入口合约或某个被声明的文件。"""

    code = "SOURCE_MISSING"


class UnresolvedImportError(AuditError):
    """合约中存在无法在已提交来源集合内解析的 import。"""

    code = "UNRESOLVED_IMPORT"


class InvalidContentError(AuditError):
    """文件内容无法被词法/语法层接受（空内容、编码非法、不可识别等）。"""

    code = "INVALID_CONTENT"


class InvalidSubmissionError(AuditError):
    """提交请求本身结构非法（空来源集合、非法路径等）。"""

    code = "INVALID_SUBMISSION"


class TaskNotFoundError(AuditError):
    """引用了一个不存在的任务。"""

    code = "TASK_NOT_FOUND"


class TaskStateError(AuditError):
    """任务当前状态不允许所请求的操作（如取消一个已完成任务）。"""

    code = "TASK_STATE_CONFLICT"


class TaskTimeoutError(AuditError):
    """任务执行超过时限。"""

    code = "TASK_TIMEOUT"
