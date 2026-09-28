"""任务与结论的持久化（SQLite），支持服务重启后恢复。

- tasks 表记录任务生命周期（含最终结论/对比结论快照），kind 区分 audit/diff；
- reports 表以输入指纹为主键缓存结论，重复提交直接命中，重启后不丢失；
- diffs 表以 (新版本指纹, 基线指纹) 为主键缓存对比结论；
- 每次操作独立连接，WAL 模式下读写并发安全。
"""
from __future__ import annotations

import json
import sqlite3
import threading

from app.models import (
    AuditReport,
    DiffCategory,
    DiffEntry,
    DiffReport,
    Finding,
    Severity,
    TaskRecord,
    TaskStatus,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tasks (
    task_id TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    status TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'audit',
    attempts INTEGER NOT NULL DEFAULT 0,
    error_code TEXT,
    error_detail TEXT,
    report_json TEXT,
    baseline_task_id TEXT,
    baseline_fingerprint TEXT,
    diff_json TEXT,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tasks_fingerprint ON tasks(fingerprint);
CREATE TABLE IF NOT EXISTS reports (
    fingerprint TEXT PRIMARY KEY,
    report_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS inputs (
    fingerprint TEXT PRIMARY KEY,
    payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS diffs (
    current_fingerprint TEXT NOT NULL,
    baseline_fingerprint TEXT NOT NULL,
    diff_id TEXT NOT NULL,
    diff_json TEXT NOT NULL,
    PRIMARY KEY (current_fingerprint, baseline_fingerprint)
);
"""

# 旧版 tasks 表 -> 新增列的轻量迁移
_MIGRATIONS = {
    "kind": "ALTER TABLE tasks ADD COLUMN kind TEXT NOT NULL DEFAULT 'audit'",
    "baseline_task_id": "ALTER TABLE tasks ADD COLUMN baseline_task_id TEXT",
    "baseline_fingerprint": "ALTER TABLE tasks ADD COLUMN baseline_fingerprint TEXT",
    "diff_json": "ALTER TABLE tasks ADD COLUMN diff_json TEXT",
}


def _finding_to_dict(f: Finding) -> dict:
    return {
        "finding_id": f.finding_id,
        "rule_ids": list(f.rule_ids),
        "severity": int(f.severity),
        "file": f.file,
        "line": f.line,
        "contract": f.contract,
        "function": f.function,
        "message": f.message,
        "signature": f.signature,
    }


def _finding_from_dict(d: dict) -> Finding:
    return Finding(
        finding_id=d["finding_id"],
        rule_ids=tuple(d["rule_ids"]),
        severity=Severity(d["severity"]),
        file=d["file"],
        line=d["line"],
        contract=d["contract"],
        function=d["function"],
        message=d["message"],
        signature=d.get("signature", ""),
    )


def _report_to_json(report: AuditReport) -> str:
    return json.dumps(
        {
            "fingerprint": report.fingerprint,
            "clean": report.clean,
            "report_hash": report.report_hash,
            "findings": [_finding_to_dict(f) for f in report.findings],
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
        findings=tuple(_finding_from_dict(f) for f in d["findings"]),
    )


def _diff_to_json(diff: DiffReport) -> str:
    return json.dumps(
        {
            "diff_id": diff.diff_id,
            "current_fingerprint": diff.current_fingerprint,
            "baseline_fingerprint": diff.baseline_fingerprint,
            "baseline_task_id": diff.baseline_task_id,
            "current_report_hash": diff.current_report_hash,
            "baseline_report_hash": diff.baseline_report_hash,
            "counts": diff.counts,
            "diff_hash": diff.diff_hash,
            "entries": [
                {
                    "category": e.category.value,
                    "signature": e.signature,
                    "rule_ids": list(e.rule_ids),
                    "baseline_finding": (
                        _finding_to_dict(e.baseline_finding)
                        if e.baseline_finding is not None else None
                    ),
                    "current_finding": (
                        _finding_to_dict(e.current_finding)
                        if e.current_finding is not None else None
                    ),
                    "baseline_severity": (
                        int(e.baseline_severity)
                        if e.baseline_severity is not None else None
                    ),
                    "current_severity": (
                        int(e.current_severity)
                        if e.current_severity is not None else None
                    ),
                }
                for e in diff.entries
            ],
        },
        ensure_ascii=False,
        sort_keys=True,
    )


def _diff_from_json(raw: str) -> DiffReport:
    d = json.loads(raw)

    def _sev(v: int | None) -> Severity | None:
        return Severity(v) if v is not None else None

    entries = tuple(
        DiffEntry(
            category=DiffCategory(e["category"]),
            signature=e["signature"],
            rule_ids=tuple(e["rule_ids"]),
            baseline_finding=(
                _finding_from_dict(e["baseline_finding"])
                if e["baseline_finding"] is not None else None
            ),
            current_finding=(
                _finding_from_dict(e["current_finding"])
                if e["current_finding"] is not None else None
            ),
            baseline_severity=_sev(e["baseline_severity"]),
            current_severity=_sev(e["current_severity"]),
        )
        for e in d["entries"]
    )
    return DiffReport(
        diff_id=d["diff_id"],
        current_fingerprint=d["current_fingerprint"],
        baseline_fingerprint=d["baseline_fingerprint"],
        baseline_task_id=d["baseline_task_id"],
        current_report_hash=d["current_report_hash"],
        baseline_report_hash=d["baseline_report_hash"],
        entries=entries,
        counts=dict(d["counts"]),
        diff_hash=d["diff_hash"],
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
            existing = {
                r[1] for r in conn.execute("PRAGMA table_info(tasks)").fetchall()
            }
            for column, stmt in _MIGRATIONS.items():
                if column not in existing:
                    conn.execute(stmt)
            # 复合索引依赖新列，须在迁移之后创建
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_tasks_pair"
                " ON tasks(fingerprint, baseline_fingerprint)"
            )

    @staticmethod
    def _row_to_record(row: sqlite3.Row | tuple) -> TaskRecord:
        (task_id, fingerprint, status, kind, attempts, error_code, error_detail,
         report_json, baseline_task_id, baseline_fingerprint, diff_json,
         created_at, updated_at) = row
        return TaskRecord(
            task_id=task_id,
            fingerprint=fingerprint,
            status=TaskStatus(status),
            kind=kind or "audit",
            attempts=attempts,
            error_code=error_code,
            error_detail=error_detail,
            report=_report_from_json(report_json) if report_json else None,
            baseline_task_id=baseline_task_id,
            baseline_fingerprint=baseline_fingerprint,
            diff=_diff_from_json(diff_json) if diff_json else None,
            created_at=created_at,
            updated_at=updated_at,
        )

    _COLUMNS = (
        "task_id, fingerprint, status, kind, attempts, error_code, error_detail,"
        " report_json, baseline_task_id, baseline_fingerprint, diff_json,"
        " created_at, updated_at"
    )

    def get_by_fingerprint(self, fingerprint: str) -> TaskRecord | None:
        """返回该指纹最早的 audit 任务（对比任务不参与单版本去重索引）。"""
        with self._lock, self._connect() as conn:
            row = conn.execute(
                f"SELECT {self._COLUMNS} FROM tasks WHERE fingerprint = ?"
                " AND kind = 'audit' ORDER BY created_at ASC LIMIT 1",
                (fingerprint,),
            ).fetchone()
        return self._row_to_record(row) if row else None

    def get_diff_task(
        self, current_fp: str, baseline_fp: str
    ) -> TaskRecord | None:
        """按 (新版本指纹, 基线指纹) 取最早的对比任务。"""
        with self._lock, self._connect() as conn:
            row = conn.execute(
                f"SELECT {self._COLUMNS} FROM tasks"
                " WHERE fingerprint = ? AND baseline_fingerprint = ?"
                " AND kind = 'diff' ORDER BY created_at ASC LIMIT 1",
                (current_fp, baseline_fp),
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
        diff_json = _diff_to_json(record.diff) if record.diff else None
        with self._lock, self._connect() as conn:
            conn.execute(
                f"INSERT INTO tasks ({self._COLUMNS})"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)"
                " ON CONFLICT(task_id) DO UPDATE SET"
                "   fingerprint=excluded.fingerprint, status=excluded.status,"
                "   kind=excluded.kind, attempts=excluded.attempts,"
                "   error_code=excluded.error_code,"
                "   error_detail=excluded.error_detail,"
                "   report_json=excluded.report_json,"
                "   baseline_task_id=excluded.baseline_task_id,"
                "   baseline_fingerprint=excluded.baseline_fingerprint,"
                "   diff_json=excluded.diff_json,"
                "   created_at=excluded.created_at, updated_at=excluded.updated_at",
                (
                    record.task_id,
                    record.fingerprint,
                    record.status.value,
                    record.kind,
                    record.attempts,
                    record.error_code,
                    record.error_detail,
                    report_json,
                    record.baseline_task_id,
                    record.baseline_fingerprint,
                    diff_json,
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

    def save_input(self, fingerprint: str, files: list[tuple[str, bytes]]) -> None:
        payload = json.dumps(
            [[path, raw.decode("latin-1")] for path, raw in files],
            ensure_ascii=False, sort_keys=True,
        )
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO inputs (fingerprint, payload_json) VALUES (?, ?)"
                " ON CONFLICT(fingerprint) DO NOTHING",
                (fingerprint, payload),
            )

    def load_input(self, fingerprint: str) -> list[tuple[str, bytes]] | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT payload_json FROM inputs WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()
        if not row:
            return None
        return [(path, text.encode("latin-1")) for path, text in json.loads(row[0])]

    def fingerprint_index(self) -> dict[str, str]:
        """返回 {指纹: 最早 audit 任务id}，用于启动时重建去重索引。"""
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT fingerprint, task_id FROM tasks WHERE kind = 'audit'"
                " GROUP BY fingerprint ORDER BY created_at ASC"
            ).fetchall()
        return dict(rows)

    def diff_pair_index(self) -> dict[tuple[str, str], str]:
        """返回 {(新版本指纹, 基线指纹): 最早 diff 任务id}，用于重启重建去重索引。"""
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT fingerprint, baseline_fingerprint, task_id FROM tasks"
                " WHERE kind = 'diff' AND baseline_fingerprint IS NOT NULL"
                " GROUP BY fingerprint, baseline_fingerprint"
                " ORDER BY created_at ASC"
            ).fetchall()
        return {(cur, base): tid for cur, base, tid in rows}

    def save_diff(self, diff: DiffReport) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO diffs (current_fingerprint, baseline_fingerprint,"
                " diff_id, diff_json) VALUES (?, ?, ?, ?)"
                " ON CONFLICT(current_fingerprint, baseline_fingerprint) DO UPDATE SET"
                "   diff_id=excluded.diff_id, diff_json=excluded.diff_json",
                (
                    diff.current_fingerprint,
                    diff.baseline_fingerprint,
                    diff.diff_id,
                    _diff_to_json(diff),
                ),
            )

    def load_diff(
        self, current_fp: str, baseline_fp: str
    ) -> DiffReport | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT diff_json FROM diffs"
                " WHERE current_fingerprint = ? AND baseline_fingerprint = ?",
                (current_fp, baseline_fp),
            ).fetchone()
        return _diff_from_json(row[0]) if row else None

    def recover_unfinished(self) -> list[TaskRecord]:
        """重启后恢复未完成任务（QUEUED/RUNNING，含 audit 与 diff）。"""
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                f"SELECT {self._COLUMNS} FROM tasks"
                " WHERE status IN (?, ?) ORDER BY created_at ASC",
                (TaskStatus.QUEUED.value, TaskStatus.RUNNING.value),
            ).fetchall()
        return [self._row_to_record(r) for r in rows]
