"""任务与结论的持久化（SQLite），支持服务重启后恢复。

- tasks 表记录任务生命周期（含最终结论快照）；
- reports 表以输入指纹为主键缓存结论，重复提交直接命中，重启后不丢失；
- 每次操作独立连接，WAL 模式下读写并发安全。
"""
from __future__ import annotations

import json
import sqlite3
import threading

from app.models import (
    AuditReport,
    CompareRecord,
    ComparisonReport,
    DeltaCategory,
    Finding,
    FindingDelta,
    FindingSide,
    IssueRef,
    Severity,
    TaskRecord,
    TaskStatus,
)

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
CREATE TABLE IF NOT EXISTS inputs (
    fingerprint TEXT PRIMARY KEY,
    payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS comparisons (
    compare_id TEXT PRIMARY KEY,
    current_fingerprint TEXT NOT NULL,
    baseline_task_id TEXT NOT NULL,
    current_task_id TEXT NOT NULL,
    status TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    error_code TEXT,
    error_detail TEXT,
    result_json TEXT,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    UNIQUE(current_fingerprint, baseline_task_id)
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
                    "issues": [
                        {
                            "rule_id": i.rule_id,
                            "issue_key": i.issue_key,
                            "severity": int(i.severity),
                        }
                        for i in f.issues
                    ],
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
                issues=tuple(
                    IssueRef(
                        rule_id=i["rule_id"],
                        issue_key=i["issue_key"],
                        severity=Severity(i["severity"]),
                    )
                    for i in f.get("issues", [])
                ),
            )
            for f in d["findings"]
        ),
    )


def _side_to_json(side: FindingSide) -> dict:
    return {
        "finding_id": side.finding_id,
        "severity": int(side.severity),
        "file": side.file,
        "line": side.line,
        "contract": side.contract,
        "function": side.function,
        "message": side.message,
    }


def _side_from_json(d: dict) -> FindingSide:
    return FindingSide(
        finding_id=d["finding_id"],
        severity=Severity(d["severity"]),
        file=d["file"],
        line=d["line"],
        contract=d["contract"],
        function=d["function"],
        message=d["message"],
    )


def _comparison_to_json(result: ComparisonReport) -> str:
    return json.dumps(
        {
            "baseline_task_id": result.baseline_task_id,
            "current_task_id": result.current_task_id,
            "baseline_fingerprint": result.baseline_fingerprint,
            "current_fingerprint": result.current_fingerprint,
            "baseline_report_hash": result.baseline_report_hash,
            "current_report_hash": result.current_report_hash,
            "comparison_hash": result.comparison_hash,
            "counts": result.counts,
            "deltas": [
                {
                    "delta_id": dl.delta_id,
                    "category": dl.category.value,
                    "rule_id": dl.rule_id,
                    "issue_key": dl.issue_key,
                    "baseline_severity": (
                        int(dl.baseline_severity)
                        if dl.baseline_severity is not None else None
                    ),
                    "current_severity": (
                        int(dl.current_severity)
                        if dl.current_severity is not None else None
                    ),
                    "baseline": (
                        _side_to_json(dl.baseline) if dl.baseline else None
                    ),
                    "current": (
                        _side_to_json(dl.current) if dl.current else None
                    ),
                }
                for dl in result.deltas
            ],
        },
        ensure_ascii=False,
        sort_keys=True,
    )


def _comparison_from_json(raw: str) -> ComparisonReport:
    d = json.loads(raw)
    deltas = tuple(
        FindingDelta(
            delta_id=dl["delta_id"],
            category=DeltaCategory(dl["category"]),
            rule_id=dl["rule_id"],
            issue_key=dl["issue_key"],
            baseline_severity=(
                Severity(dl["baseline_severity"])
                if dl["baseline_severity"] is not None else None
            ),
            current_severity=(
                Severity(dl["current_severity"])
                if dl["current_severity"] is not None else None
            ),
            baseline=(
                _side_from_json(dl["baseline"]) if dl.get("baseline") else None
            ),
            current=(
                _side_from_json(dl["current"]) if dl.get("current") else None
            ),
        )
        for dl in d["deltas"]
    )
    return ComparisonReport(
        baseline_task_id=d["baseline_task_id"],
        current_task_id=d["current_task_id"],
        baseline_fingerprint=d["baseline_fingerprint"],
        current_fingerprint=d["current_fingerprint"],
        baseline_report_hash=d["baseline_report_hash"],
        current_report_hash=d["current_report_hash"],
        deltas=deltas,
        counts={k: int(v) for k, v in d["counts"].items()},
        comparison_hash=d["comparison_hash"],
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
        """返回 {指纹: 最早任务id}，用于启动时重建去重索引。"""
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT fingerprint, task_id FROM tasks"
                " GROUP BY fingerprint ORDER BY created_at ASC"
            ).fetchall()
        return dict(rows)

    def recover_unfinished(self) -> list[TaskRecord]:
        """重启后恢复未完成任务（QUEUED/RUNNING）。"""
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                f"SELECT {self._COLUMNS} FROM tasks"
                " WHERE status IN (?, ?) ORDER BY created_at ASC",
                (TaskStatus.QUEUED.value, TaskStatus.RUNNING.value),
            ).fetchall()
        return [self._row_to_record(r) for r in rows]

    # ---------- 版本对比记录 ----------

    _CMP_COLUMNS = (
        "compare_id, current_fingerprint, baseline_task_id, current_task_id,"
        " status, attempts, error_code, error_detail, result_json,"
        " created_at, updated_at"
    )

    def _row_to_compare(self, row: sqlite3.Row | tuple) -> CompareRecord:
        (compare_id, current_fp, baseline_id, current_id, status, attempts,
         error_code, error_detail, result_json, created_at, updated_at) = row
        return CompareRecord(
            compare_id=compare_id,
            current_fingerprint=current_fp,
            baseline_task_id=baseline_id,
            current_task_id=current_id,
            status=TaskStatus(status),
            attempts=attempts,
            error_code=error_code,
            error_detail=error_detail,
            result=_comparison_from_json(result_json) if result_json else None,
            created_at=created_at,
            updated_at=updated_at,
        )

    def get_compare(self, compare_id: str) -> CompareRecord | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                f"SELECT {self._CMP_COLUMNS} FROM comparisons WHERE compare_id = ?",
                (compare_id,),
            ).fetchone()
        return self._row_to_compare(row) if row else None

    def get_compare_by_pair(
        self, current_fingerprint: str, baseline_task_id: str
    ) -> CompareRecord | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                f"SELECT {self._CMP_COLUMNS} FROM comparisons"
                " WHERE current_fingerprint = ? AND baseline_task_id = ?",
                (current_fingerprint, baseline_task_id),
            ).fetchone()
        return self._row_to_compare(row) if row else None

    def upsert_compare(self, rec: CompareRecord) -> None:
        result_json = _comparison_to_json(rec.result) if rec.result else None
        with self._lock, self._connect() as conn:
            conn.execute(
                f"INSERT INTO comparisons ({self._CMP_COLUMNS})"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)"
                " ON CONFLICT(compare_id) DO UPDATE SET"
                "   current_fingerprint=excluded.current_fingerprint,"
                "   baseline_task_id=excluded.baseline_task_id,"
                "   current_task_id=excluded.current_task_id,"
                "   status=excluded.status, attempts=excluded.attempts,"
                "   error_code=excluded.error_code,"
                "   error_detail=excluded.error_detail,"
                "   result_json=excluded.result_json,"
                "   updated_at=excluded.updated_at",
                (
                    rec.compare_id,
                    rec.current_fingerprint,
                    rec.baseline_task_id,
                    rec.current_task_id,
                    rec.status.value,
                    rec.attempts,
                    rec.error_code,
                    rec.error_detail,
                    result_json,
                    rec.created_at,
                    rec.updated_at,
                ),
            )

    def recover_unfinished_comparisons(self) -> list[CompareRecord]:
        """重启后恢复未完成对比任务（QUEUED/RUNNING）。"""
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                f"SELECT {self._CMP_COLUMNS} FROM comparisons"
                " WHERE status IN (?, ?) ORDER BY created_at ASC",
                (TaskStatus.QUEUED.value, TaskStatus.RUNNING.value),
            ).fetchall()
        return [self._row_to_compare(r) for r in rows]
