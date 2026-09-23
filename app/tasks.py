"""任务管理：去重、排队、超时、取消、重试，任意并发时序下状态自洽。

设计要点
--------
- 内容寻址去重：任务以输入指纹为主键，重复提交（无论多少次、什么并发时序）
  永远返回同一个 TaskRecord，不会产生重复结论。
- 状态 CAS：执行线程在开始与完成时均做 (状态, attempts 令牌) 校验，
  取消/超时/重试与执行完成的任意交错都不会写出过期结论。
- 超时：看门狗线程等待执行 future；超时只做状态标记，过期结果在 CAS 处丢弃。
- 恢复：输入载荷与结论均持久化，重启后未完成任务重新入队，已完成结论直接复用。
"""
from __future__ import annotations

import threading
import time
import uuid
from concurrent.futures import Future, ThreadPoolExecutor

from app import engine
from app.errors import IngestError
from app.ingest import decode_sources, fingerprint, normalize_sources, resolve_imports
from app.models import ErrorCode, TaskRecord, TaskStatus
from app.store import TaskStore

_RETRIABLE_STATES = frozenset(
    {TaskStatus.FAILED, TaskStatus.TIMEOUT, TaskStatus.CANCELLED}
)
_RUNNABLE_STATES = frozenset({TaskStatus.QUEUED, TaskStatus.RUNNING})


def record_to_dict(rec: TaskRecord) -> dict:
    """把任务记录序列化为稳定的 JSON 结构。"""
    d: dict = {
        "task_id": rec.task_id,
        "fingerprint": rec.fingerprint,
        "status": rec.status.value,
        "attempts": rec.attempts,
        "error_code": rec.error_code,
        "error_detail": rec.error_detail,
        "created_at": rec.created_at,
        "updated_at": rec.updated_at,
    }
    if rec.report is not None:
        d["report"] = {
            "fingerprint": rec.report.fingerprint,
            "clean": rec.report.clean,
            "report_hash": rec.report.report_hash,
            "findings": [
                {
                    "finding_id": f.finding_id,
                    "rule_ids": list(f.rule_ids),
                    "severity": f.severity.name,
                    "file": f.file,
                    "line": f.line,
                    "contract": f.contract,
                    "function": f.function,
                    "message": f.message,
                }
                for f in rec.report.findings
            ],
        }
    return d


class TaskManager:
    """审计任务生命周期管理器。"""

    def __init__(
        self,
        store: TaskStore,
        timeout_seconds: float = 30.0,
        max_attempts: int = 3,
        worker_count: int = 4,
        auto_recover: bool = True,
    ) -> None:
        self._store = store
        self._timeout = timeout_seconds
        self._max_attempts = max_attempts
        self._lock = threading.RLock()
        self._index: dict[str, str] = store.fingerprint_index()
        self._runner = ThreadPoolExecutor(
            max_workers=worker_count, thread_name_prefix="audit-run"
        )
        self._watcher = ThreadPoolExecutor(
            max_workers=32, thread_name_prefix="audit-watch"
        )
        if auto_recover:
            self.recover()

    # ---------- 内部：调度 ----------

    def _enqueue(self, task_id: str) -> None:
        future = self._runner.submit(self._run_task, task_id)
        self._watcher.submit(self._watch, task_id, future)

    def _watch(self, task_id: str, future: Future) -> None:
        try:
            future.result(timeout=self._timeout)
        except TimeoutError:
            with self._lock:
                rec = self._store.get(task_id)
                if rec is not None and rec.status in _RUNNABLE_STATES:
                    rec.status = TaskStatus.TIMEOUT
                    rec.error_code = ErrorCode.TASK_TIMEOUT.value
                    rec.error_detail = (
                        f"任务在 {self._timeout}s 内未完成，已标记超时"
                    )
                    rec.updated_at = time.time()
                    self._store.upsert(rec)
        except Exception:  # 执行内部已自行落库状态；看门狗静默
            pass

    def _run_task(self, task_id: str) -> None:
        with self._lock:
            rec = self._store.get(task_id)
            if rec is None or rec.status is not TaskStatus.QUEUED:
                return  # 已取消/超时/重试的过期调度，不计算
            rec.status = TaskStatus.RUNNING
            rec.attempts += 1
            rec.error_code = None
            rec.error_detail = None
            rec.updated_at = time.time()
            token = rec.attempts
            self._store.upsert(rec)
            fp = rec.fingerprint

        # 审计计算在锁外执行，避免阻塞提交/取消
        try:
            files = self._store.load_input(fp)
            sources = normalize_sources(decode_sources(files or []))
            report = engine.audit(
                fp, sources, resolve_imports(sources)
            )
        except Exception as exc:  # 任何分析异常都转为 FAILED，可重试
            with self._lock:
                cur = self._store.get(task_id)
                if (
                    cur is None
                    or cur.status is not TaskStatus.RUNNING
                    or cur.attempts != token
                ):
                    return
                cur.status = TaskStatus.FAILED
                cur.error_code = ErrorCode.INTERNAL_ERROR.value
                cur.error_detail = f"审计执行失败: {exc}"
                cur.updated_at = time.time()
                self._store.upsert(cur)
            return

        with self._lock:
            cur = self._store.get(task_id)
            if (
                cur is None
                or cur.status is not TaskStatus.RUNNING
                or cur.attempts != token
            ):
                return  # 执行期间被取消/超时/重试，丢弃过期结论
            cur.status = TaskStatus.SUCCEEDED
            cur.report = report
            cur.error_code = None
            cur.error_detail = None
            cur.updated_at = time.time()
            self._store.save_report(fp, report)
            self._store.upsert(cur)

    # ---------- 公共 API ----------

    def submit(self, files: list[tuple[str, bytes]]) -> TaskRecord:
        """提交审计任务；相同内容（任意并发时序）返回同一任务，不重复计算。

        接入失败（来源缺失/导入不可解析/内容非法）直接抛 IngestError，
        不会创建任何任务或半成品结论。
        """
        # 先做完整校验，任何失败都在入队之前拒绝
        sources = normalize_sources(decode_sources(files))
        ordered = resolve_imports(sources)
        fp = fingerprint(sources)
        now = time.time()

        with self._lock:
            existing_id = self._index.get(fp)
            if existing_id is not None:
                existing = self._store.get(existing_id)
                if existing is not None:
                    return existing
            cached = self._store.load_report(fp)
            task_id = uuid.uuid4().hex
            if cached is not None:
                rec = TaskRecord(
                    task_id=task_id,
                    fingerprint=fp,
                    status=TaskStatus.SUCCEEDED,
                    report=cached,
                    created_at=now,
                    updated_at=now,
                )
            else:
                rec = TaskRecord(
                    task_id=task_id,
                    fingerprint=fp,
                    status=TaskStatus.QUEUED,
                    created_at=now,
                    updated_at=now,
                )
            self._store.save_input(fp, files)
            self._store.upsert(rec)
            self._index[fp] = task_id
            if rec.status is TaskStatus.QUEUED:
                self._enqueue(task_id)
            return rec

    def get(self, task_id: str) -> TaskRecord | None:
        with self._lock:
            return self._store.get(task_id)

    def wait_for(self, task_id: str, poll: float = 0.01,
                 deadline: float = 10.0) -> TaskRecord | None:
        """阻塞直到任务进入终态（测试/同步客户端用）。"""
        end = time.time() + deadline
        while time.time() < end:
            rec = self.get(task_id)
            if rec is not None and rec.status in (
                TaskStatus.SUCCEEDED,
                TaskStatus.FAILED,
                TaskStatus.CANCELLED,
                TaskStatus.TIMEOUT,
            ):
                return rec
            time.sleep(poll)
        return self.get(task_id)

    def cancel(self, task_id: str) -> TaskRecord | None:
        """取消排队中或运行中的任务；终态任务保持不变。"""
        with self._lock:
            rec = self._store.get(task_id)
            if rec is None:
                return None
            if rec.status in _RUNNABLE_STATES:
                rec.status = TaskStatus.CANCELLED
                rec.error_code = ErrorCode.TASK_CANCELLED.value
                rec.error_detail = "任务被客户端取消"
                rec.updated_at = time.time()
                self._store.upsert(rec)
            return rec

    def retry(self, task_id: str) -> TaskRecord | None:
        """对失败/超时/取消的任务发起重试，受 max_attempts 限制。"""
        with self._lock:
            rec = self._store.get(task_id)
            if rec is None:
                return None
            if rec.status not in _RETRIABLE_STATES:
                return rec
            if rec.attempts >= self._max_attempts:
                raise RuntimeError(
                    f"任务已达到最大尝试次数 {self._max_attempts}，拒绝重试"
                )
            rec.status = TaskStatus.QUEUED
            rec.error_code = None
            rec.error_detail = None
            rec.updated_at = time.time()
            self._store.upsert(rec)
            self._enqueue(task_id)
            return rec

    def recover(self) -> list[TaskRecord]:
        """服务重启后恢复未完成任务：RUNNING 视为未完成并重新入队。"""
        records = self._store.recover_unfinished()
        with self._lock:
            for rec in records:
                rec.status = TaskStatus.QUEUED
                rec.error_code = None
                rec.error_detail = None
                rec.updated_at = time.time()
                self._store.upsert(rec)
                self._enqueue(rec.task_id)
        return records

    def shutdown(self) -> None:
        self._runner.shutdown(wait=False, cancel_futures=True)
        self._watcher.shutdown(wait=False, cancel_futures=True)
