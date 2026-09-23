"""任务与结论的持久化（SQLite），支持服务重启后恢复。

- tasks 表记录任务生命周期（含最终结论快照）；
- reports 表以输入指纹为主键缓存结论，重复提交直接命中，重启后不丢失；
- 每次操作独立连接，WAL 模式下读写并发安全。
"""
from __future__ import annotations

import json
import sqlite3
import threading

from app.models import AuditReport, Finding, Severity, TaskRecord, TaskStatus

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tasks (
    task_id TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    status TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    error_code TEXT,
    error_detail TEXT,
    report_json TEXT,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tasks_fingerprint ON tasks(fingerprint);
CREATE TABLE IF NOT EXISTS reports (
    fingerprint TEXT PRIMARY KEY,
    report_json TEXT NOT NULL
);
"""


def _report_to_json(report: AuditReport) -> str:
    return json.dumps(
        {
            "fingerprint": report.fingerprint,
            "clean": report.clean,
            "report_hash": report.report_hash,
            "findings": [
                {
                    "finding_id": f.finding_id,
                    "rule_ids": list(f.rule_ids),
                    "severity": int(f.severity),
                    "file": f.file,
                    "line": f.line,
                    "contract": f.contract,
                    "function": f.function,
                    "message": f.message,
                }
                for f in report.findings
            ],
        },
        ensure_ascii=False,
        sort_keys=True,
    )


def _report_from_json(raw: str) -> AuditReport:
    d = json.loads(raw)
    return AuditReport(
        fingerprint=d["fingerprint"],
        clean=d["clean"],
        report_hash=d["report_hash"],
        findings=tuple(
            Finding(
                finding_id=f["finding_id"],
                rule_ids=tuple(f["rule_ids"]),
                severity=Severity(f["severity"]),
                file=f["file"],
                line=f["line"],
                contract=f["contract"],
                function=f["function"],
                message=f["message"],
            )
            for f in d["findings"]
        ),
    )


class TaskStore:
    """基于 SQLite 的任务存储；已完成结论与未完成任务均可恢复。"""

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        self.init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def init_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(_SCHEMA)

    @staticmethod
    def _row_to_record(row: sqlite3.Row | tuple) -> TaskRecord:
        (task_id, fingerprint, status, attempts, error_code, error_detail,
         report_json, created_at, updated_at) = row
        return TaskRecord(
            task_id=task_id,
            fingerprint=fingerprint,
            status=TaskStatus(status),
            attempts=attempts,
            error_code=error_code,
            error_detail=error_detail,
            report=_report_from_json(report_json) if report_json else None,
            created_at=created_at,
            updated_at=updated_at,
        )

    _COLUMNS = (
        "task_id, fingerprint, status, attempts, error_code, error_detail,"
        " report_json, created_at, updated_at"
    )

    def get_by_fingerprint(self, fingerprint: str) -> TaskRecord | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                f"SELECT {self._COLUMNS} FROM tasks WHERE fingerprint = ?"
                " ORDER BY created_at ASC LIMIT 1",
                (fingerprint,),
            ).fetchone()
        return self._row_to_record(row) if row else None

    def get(self, task_id: str) -> TaskRecord | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                f"SELECT {self._COLUMNS} FROM tasks WHERE task_id = ?",
                (task_id,),
            ).fetchone()
        return self._row_to_record(row) if row else None

    def upsert(self, record: TaskRecord) -> None:
        report_json = _report_to_json(record.report) if record.report else None
        with self._lock, self._connect() as conn:
            conn.execute(
                f"INSERT INTO tasks ({self._COLUMNS})"
                " VALUES (?,?,?,?,?,?,?,?,?)"
                " ON CONFLICT(task_id) DO UPDATE SET"
                "   fingerprint=excluded.fingerprint, status=excluded.status,"
                "   attempts=excluded.attempts, error_code=excluded.error_code,"
                "   error_detail=excluded.error_detail,"
                "   report_json=excluded.report_json,"
                "   created_at=excluded.created_at, updated_at=excluded.updated_at",
                (
                    record.task_id,
                    record.fingerprint,
                    record.status.value,
                    record.attempts,
                    record.error_code,
                    record.error_detail,
                    report_json,
                    record.created_at,
                    record.updated_at,
                ),
            )

    def save_report(self, fingerprint: str, report: AuditReport) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO reports (fingerprint, report_json) VALUES (?, ?)"
                " ON CONFLICT(fingerprint) DO UPDATE SET report_json=excluded.report_json",
                (fingerprint, _report_to_json(report)),
            )

    def load_report(self, fingerprint: str) -> AuditReport | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT report_json FROM reports WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()
        return _report_from_json(row[0]) if row else None

    def recover_unfinished(self) -> list[TaskRecord]:
        """重启后恢复未完成任务（QUEUED/RUNNING）。"""
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                f"SELECT {self._COLUMNS} FROM tasks"
                " WHERE status IN (?, ?) ORDER BY created_at ASC",
                (TaskStatus.QUEUED.value, TaskStatus.RUNNING.value),
            ).fetchall()
        return [self._row_to_record(r) for r in rows]
