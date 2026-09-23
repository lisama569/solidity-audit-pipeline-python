"""任务与结论的 SQLite 持久化。

- 以 content_hash 作为唯一键保证"相同合约重复提交不产生重复结论"；
- 任务状态、报告、错误信息全部落盘，服务重启后 COMPLETED 结论直接可读，
  QUEUED 任务可被重新领取，RUNNING 的遗留任务在启动时回滚为 QUEUED；
- 所有状态变更在单连接事务内完成（WAL + 检查外的 threading 串行化由
  service 层锁负责），崩溃时不会出现半写状态。
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from typing import Optional

from .models import (
    AuditReport,
    Finding,
    Location,
    Severity,
    SourceFile,
    Task,
    TaskState,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tasks (
    id             TEXT PRIMARY KEY,
    content_hash   TEXT NOT NULL UNIQUE,
    state          TEXT NOT NULL,
    entry_point    TEXT NOT NULL,
    sources        TEXT NOT NULL,
    attempts       INTEGER NOT NULL,
    max_attempts   INTEGER NOT NULL,
    created_at     REAL NOT NULL,
    updated_at     REAL NOT NULL,
    started_at     REAL,
    deadline       REAL,
    report         TEXT,
    error          TEXT,
    client_labels  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tasks_state ON tasks(state);
"""


class TaskStore:
    def __init__(self, db_path: str = ":memory:") -> None:
        self.db_path = db_path
        # worker 在独立线程访问同一连接，必须关闭同线程限制；
        # service 层的服务锁保证所有事务串行化，因此跨线程使用是安全的。
        self._conn = sqlite3.connect(
            db_path, check_same_thread=False, isolation_level=None
        )
        self._conn.row_factory = sqlite3.Row
        # sqlite3 连接跨线程共享时，语句的参数绑定不是线程安全的：
        # 两个并发写可能交错绑定参数，导致同一行的列被写乱（实测出现
        # state=NULL、client_labels=NULL）。用一把锁把所有 DB 操作串行化。
        self._db_lock = threading.RLock()
        with self._db_lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self.init_schema()

    # ------------------------------------------------------------ schema

    def init_schema(self) -> None:
        with self._db_lock:
            self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        with self._db_lock:
            self._conn.close()

    # ------------------------------------------------------------ serialize

    @staticmethod
    def _report_to_json(report: AuditReport | None) -> str | None:
        return json.dumps(report.to_dict(), ensure_ascii=False, sort_keys=True) if report else None

    @staticmethod
    def _report_from_json(blob: str | None) -> AuditReport | None:
        if not blob:
            return None
        data = json.loads(blob)
        findings = []
        for fd in data["findings"]:
            locs = [Location(**ld) for ld in fd["locations"]]
            findings.append(
                Finding(
                    key=fd["key"],
                    rule_ids=list(fd["rule_ids"]),
                    category=fd["category"],
                    title=fd["title"],
                    severity=Severity(fd["severity"]),
                    description=fd["description"],
                    locations=locs,
                    evidence=list(fd["evidence"]),
                    id=fd["id"],
                )
            )
        return AuditReport(
            content_hash=data["content_hash"],
            findings=findings,
            rules_evaluated=list(data["rules_evaluated"]),
            no_findings=bool(data["no_findings"]),
            conclusion=data["conclusion"],
        )

    def _row_to_task(self, row: sqlite3.Row) -> Task:
        return Task(
            id=row["id"],
            content_hash=row["content_hash"],
            state=TaskState(row["state"]),
            entry_point=row["entry_point"],
            sources=json.loads(row["sources"]),
            attempts=row["attempts"],
            max_attempts=row["max_attempts"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            started_at=row["started_at"],
            deadline=row["deadline"],
            report=self._report_from_json(row["report"]),
            error=json.loads(row["error"]) if row["error"] else None,
            client_labels=json.loads(row["client_labels"]),
        )

    # ------------------------------------------------------------ CRUD

    def save(self, task: Task) -> None:
        """upsert 任务（调用方负责加锁与状态合法性）。"""
        task.updated_at = time.time()
        params = (
                task.id,
                task.content_hash,
                task.state.value,
                task.entry_point,
                json.dumps(task.sources, ensure_ascii=False, sort_keys=True),
                task.attempts,
                task.max_attempts,
                task.created_at,
                task.updated_at,
                task.started_at,
                task.deadline,
                self._report_to_json(task.report),
                json.dumps(task.error, ensure_ascii=False, sort_keys=True) if task.error else None,
                json.dumps(task.client_labels, ensure_ascii=False, sort_keys=True),
        )
        with self._db_lock:
            self._conn.execute(
                """
            INSERT INTO tasks (id, content_hash, state, entry_point, sources,
                               attempts, max_attempts, created_at, updated_at,
                               started_at, deadline, report, error, client_labels)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
                content_hash=excluded.content_hash,
                state=excluded.state,
                entry_point=excluded.entry_point,
                sources=excluded.sources,
                attempts=excluded.attempts,
                max_attempts=excluded.max_attempts,
                created_at=excluded.created_at,
                updated_at=excluded.updated_at,
                started_at=excluded.started_at,
                deadline=excluded.deadline,
                report=excluded.report,
                error=excluded.error,
                client_labels=excluded.client_labels
            """,
                params,
            )

    def get(self, task_id: str) -> Task | None:
        with self._db_lock:
            row = self._conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        return self._row_to_task(row) if row else None

    def get_by_hash(self, content_hash: str) -> Task | None:
        with self._db_lock:
            row = self._conn.execute(
                "SELECT * FROM tasks WHERE content_hash = ?", (content_hash,)
            ).fetchone()
        return self._row_to_task(row) if row else None

    def all_tasks(self) -> list[Task]:
        with self._db_lock:
            rows = self._conn.execute("SELECT * FROM tasks ORDER BY created_at, id").fetchall()
        return [self._row_to_task(r) for r in rows]

    def tasks_in_states(self, *states: TaskState) -> list[Task]:
        if not states:
            return []
        marks = ",".join("?" for _ in states)
        with self._db_lock:
            rows = self._conn.execute(
                f"SELECT * FROM tasks WHERE state IN ({marks}) ORDER BY created_at, id",
                [s.value for s in states],
            ).fetchall()
        return [self._row_to_task(r) for r in rows]
