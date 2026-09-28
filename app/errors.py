"""接入阶段的错误类型，携带可区分的失败原因。"""
from __future__ import annotations

from app.models import ErrorCode


class IngestError(Exception):
    """来源接入/归一失败。"""

    def __init__(self, code: ErrorCode, detail: str) -> None:
        super().__init__(f"{code.value}: {detail}")
        self.code = code
        self.detail = detail


class BaselineError(Exception):
    """版本对比时基线不可用；原因彼此可区分，不会降级为单版本审计。"""

    def __init__(self, code: ErrorCode, detail: str) -> None:
        super().__init__(f"{code.value}: {detail}")
        self.code = code
        self.detail = detail
