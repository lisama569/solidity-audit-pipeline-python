"""任务与结论的持久化（SQLite），支持服务重启后恢复。"""
from __future__ import annotations

import sqlite3

from app.models import AuditReport, TaskRecord


class TaskStore:
    """基于 SQLite 的任务存储；已完成结论与未完成任务均可恢复。"""

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path

    def _connect(self) -> sqlite3.Connection:
        raise NotImplementedError

    def init_schema(self) -> None:
        raise NotImplementedError

    def get_by_fingerprint(self, fingerprint: str) -> TaskRecord | None:
        raise NotImplementedError

    def get(self, task_id: str) -> TaskRecord | None:
        raise NotImplementedError

    def upsert(self, record: TaskRecord) -> None:
        raise NotImplementedError

    def save_report(self, fingerprint: str, report: AuditReport) -> None:
        raise NotImplementedError

    def load_report(self, fingerprint: str) -> AuditReport | None:
        raise NotImplementedError

    def recover_unfinished(self) -> list[TaskRecord]:
        """重启后恢复未完成任务（QUEUED/RUNNING）。"""
        raise NotImplementedError
