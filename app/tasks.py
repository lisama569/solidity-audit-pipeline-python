"""任务管理：去重、排队、超时、取消、重试，任意并发时序下状态自洽。"""
from __future__ import annotations

from app.models import TaskRecord
from app.store import TaskStore


class TaskManager:
    """审计任务生命周期管理器。"""

    def __init__(self, store: TaskStore, timeout_seconds: float = 30.0, max_attempts: int = 3) -> None:
        self._store = store
        self._timeout = timeout_seconds
        self._max_attempts = max_attempts

    def submit(self, files: list[tuple[str, bytes]]) -> TaskRecord:
        """提交审计任务；相同内容重复提交返回已有任务/结论。"""
        raise NotImplementedError

    def get(self, task_id: str) -> TaskRecord | None:
        raise NotImplementedError

    def cancel(self, task_id: str) -> TaskRecord | None:
        """取消排队中或运行中的任务。"""
        raise NotImplementedError

    def retry(self, task_id: str) -> TaskRecord | None:
        """对失败/超时任务发起重试。"""
        raise NotImplementedError

    def recover(self) -> list[TaskRecord]:
        """服务重启后恢复未完成任务。"""
        raise NotImplementedError

    def shutdown(self) -> None:
        raise NotImplementedError
