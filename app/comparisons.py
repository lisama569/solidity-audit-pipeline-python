"""版本对比任务管理：校验基线、去重、排队、超时、取消、重试与重启恢复。

对比结论是两份已完成审计报告的纯函数（见 app.diffing），因此：
- 去重键为 (新版本指纹, 基线任务id)；同一新版本对不同基线各自独立；
- 已完成对比持久化在 comparisons 表，重复/并发提交复用同一结论；
- 生命周期语义与普通审计任务一致：状态 CAS 令牌防止过期结果写入。

基线相关的拒绝在创建任何对比任务之前发生，返回可区分的失败码，
不会降级为单版本审计，也不会留下半成品记录。
"""
from __future__ import annotations

import threading
import time
import uuid
from concurrent.futures import Future, ThreadPoolExecutor

from app import diffing
from app.errors import IngestError
from app.ingest import decode_sources, fingerprint, normalize_sources, resolve_imports
from app.models import CompareRecord, DeltaCategory, ErrorCode, TaskStatus
from app.store import TaskStore
from app.tasks import TaskManager

_RETRIABLE_STATES = frozenset(
    {TaskStatus.FAILED, TaskStatus.TIMEOUT, TaskStatus.CANCELLED}
)
_RUNNABLE_STATES = frozenset({TaskStatus.QUEUED, TaskStatus.RUNNING})
_TERMINAL = frozenset(
    {TaskStatus.SUCCEEDED, TaskStatus.FAILED,
     TaskStatus.CANCELLED, TaskStatus.TIMEOUT}
)


def comparison_to_dict(rec: CompareRecord) -> dict:
    """把对比记录序列化为稳定的 JSON 结构。"""
    d: dict = {
        "compare_id": rec.compare_id,
        "current_task_id": rec.current_task_id,
        "baseline_task_id": rec.baseline_task_id,
        "current_fingerprint": rec.current_fingerprint,
        "status": rec.status.value,
        "attempts": rec.attempts,
        "error_code": rec.error_code,
        "error_detail": rec.error_detail,
        "created_at": rec.created_at,
        "updated_at": rec.updated_at,
    }
    if rec.result is not None:
        r = rec.result
        d["result"] = {
            "baseline_task_id": r.baseline_task_id,
            "current_task_id": r.current_task_id,
            "baseline_fingerprint": r.baseline_fingerprint,
            "current_fingerprint": r.current_fingerprint,
            "baseline_report_hash": r.baseline_report_hash,
            "current_report_hash": r.current_report_hash,
            "comparison_hash": r.comparison_hash,
            "counts": dict(r.counts),
            "deltas": [
                {
                    "delta_id": dl.delta_id,
                    "category": dl.category.value,
                    "rule_id": dl.rule_id,
                    "issue_key": dl.issue_key,
                    "baseline_severity": (
                        dl.baseline_severity.name
                        if dl.baseline_severity is not None else None
                    ),
                    "current_severity": (
                        dl.current_severity.name
                        if dl.current_severity is not None else None
                    ),
                    "baseline": (
                        {
                            "finding_id": dl.baseline.finding_id,
                            "severity": dl.baseline.severity.name,
                            "file": dl.baseline.file,
                            "line": dl.baseline.line,
                            "contract": dl.baseline.contract,
                            "function": dl.baseline.function,
                            "message": dl.baseline.message,
                        }
                        if dl.baseline else None
                    ),
                    "current": (
                        {
                            "finding_id": dl.current.finding_id,
                            "severity": dl.current.severity.name,
                            "file": dl.current.file,
                            "line": dl.current.line,
                            "contract": dl.current.contract,
                            "function": dl.current.function,
                            "message": dl.current.message,
                        }
                        if dl.current else None
                    ),
                }
                for dl in r.deltas
            ],
        }
    return d


class ComparisonManager:
    """版本对比任务生命周期管理器。"""

    def __init__(
        self,
        store: TaskStore,
        tasks: TaskManager,
        timeout_seconds: float = 30.0,
        max_attempts: int = 3,
        worker_count: int = 4,
        auto_recover: bool = True,
    ) -> None:
        self._store = store
        self._tasks = tasks
        self._timeout = timeout_seconds
        self._max_attempts = max_attempts
        self._lock = threading.RLock()
        self._index: dict[tuple[str, str], str] = {}
        self._runner = ThreadPoolExecutor(
            max_workers=worker_count, thread_name_prefix="cmp-run"
        )
        self._watcher = ThreadPoolExecutor(
            max_workers=32, thread_name_prefix="cmp-watch"
        )
        if auto_recover:
            self.recover()

    # ---------- 内部：校验 ----------

    def _validate(
        self, files: list[tuple[str, bytes]], baseline_task_id: str
    ) -> tuple[dict[str, str], str, "object"]:
        """返回 (归一来源, 新版本指纹, 基线记录)；任何不满足都明确拒绝。"""
        # 新版本本身先做完整接入校验（畸形输入在创建任务前拒绝）
        sources = normalize_sources(decode_sources(files))
        resolve_imports(sources)  # 导入闭包校验
        current_fp = fingerprint(sources)

        baseline = self._store.get(baseline_task_id)
        if baseline is None:
            raise IngestError(
                ErrorCode.BASELINE_NOT_FOUND,
                f"基线任务 {baseline_task_id!r} 不存在",
            )
        if baseline.status is not TaskStatus.SUCCEEDED or baseline.report is None:
            raise IngestError(
                ErrorCode.BASELINE_NOT_READY,
                f"基线任务 {baseline_task_id[:8]} 尚未审计完成"
                f"（当前状态 {baseline.status.value}）",
            )
        # 基线必须与当前提交“对得上”：同一项目演进，至少共享一个文件
        base_input = self._store.load_input(baseline.fingerprint)
        if base_input is None:
            raise IngestError(
                ErrorCode.BASELINE_MISMATCH,
                "基线提交的输入载荷缺失，无法确认与当前提交同源",
            )
        base_sources = normalize_sources(decode_sources(base_input))
        shared = set(base_sources) & set(sources)
        if not shared:
            raise IngestError(
                ErrorCode.BASELINE_MISMATCH,
                "当前提交与基线没有任何同名文件，不属于同一份合约的演进",
            )
        return sources, current_fp, baseline

    # ---------- 内部：调度 ----------

    def _enqueue(self, compare_id: str) -> None:
        future = self._runner.submit(self._run_compare, compare_id)
        self._watcher.submit(self._watch, compare_id, future)

    def _watch(self, compare_id: str, future: Future) -> None:
        try:
            future.result(timeout=self._timeout)
        except TimeoutError:
            with self._lock:
                rec = self._store.get_compare(compare_id)
                if rec is not None and rec.status in _RUNNABLE_STATES:
                    rec.status = TaskStatus.TIMEOUT
                    rec.error_code = ErrorCode.TASK_TIMEOUT.value
                    rec.error_detail = f"对比任务在 {self._timeout}s 内未完成"
                    rec.updated_at = time.time()
                    self._store.upsert_compare(rec)
        except Exception:
            pass

    def _fail(self, rec: CompareRecord, token: int, code: ErrorCode,
              detail: str) -> None:
        cur = self._store.get_compare(rec.compare_id)
        if (cur is None or cur.status is not TaskStatus.RUNNING
                or cur.attempts != token):
            return
        cur.status = TaskStatus.FAILED
        cur.error_code = code.value
        cur.error_detail = detail
        cur.updated_at = time.time()
        self._store.upsert_compare(cur)

    def _run_compare(self, compare_id: str) -> None:
        with self._lock:
            rec = self._store.get_compare(compare_id)
            if rec is None or rec.status is not TaskStatus.QUEUED:
                return  # 过期调度
            rec.status = TaskStatus.RUNNING
            rec.attempts += 1
            rec.error_code = None
            rec.error_detail = None
            rec.updated_at = time.time()
            token = rec.attempts
            self._store.upsert_compare(rec)
            current_id = rec.current_task_id
            baseline_id = rec.baseline_task_id

        # 等待新版本审计与基线就绪（二者都必须 SUCCEEDED 才对比）
        end = time.time() + self._timeout
        baseline_rec = self._store.get(baseline_id)
        while time.time() < end:
            cur_task = self._store.get(current_id)
            baseline_rec = self._store.get(baseline_id)
            with self._lock:
                me = self._store.get_compare(compare_id)
                cancelled = me is None or me.status not in _RUNNABLE_STATES
            if cancelled:
                return
            if (cur_task is not None
                    and cur_task.status is TaskStatus.SUCCEEDED
                    and baseline_rec is not None
                    and baseline_rec.status is TaskStatus.SUCCEEDED):
                break
            if (cur_task is not None
                    and cur_task.status in _RETRIABLE_STATES):
                with self._lock:
                    self._fail(
                        rec, token, ErrorCode.NEW_VERSION_NOT_READY,
                        f"新版本审计处于 {cur_task.status.value}，"
                        "无法生成对比；可先重试新版本审计后再重试对比",
                    )
                return
            time.sleep(0.02)
        else:
            with self._lock:
                self._fail(rec, token, ErrorCode.NEW_VERSION_NOT_READY,
                           "等待新版本/基线审计完成超时")
            return

        # 就绪后先在锁内做令牌校验并取出两份报告，计算放到锁外，
        # 避免慢对比阻塞提交/取消（与普通审计任务的 CAS 模式一致）。
        with self._lock:
            rec = self._store.get_compare(compare_id)
            if (rec is None or rec.status is not TaskStatus.RUNNING
                    or rec.attempts != token):
                return  # 被取消/超时/重试，丢弃
            current_task = self._store.get(current_id)
            if (current_task is None or current_task.report is None
                    or baseline_rec is None or baseline_rec.report is None):
                self._fail(rec, token, ErrorCode.NEW_VERSION_NOT_READY,
                           "新版本或基线结论缺失")
                return
            base_report = baseline_rec.report
            cur_report = current_task.report

        try:
            result = diffing.compare_reports(
                baseline=base_report,
                current=cur_report,
                baseline_task_id=baseline_id,
                current_task_id=current_id,
            )
        except Exception as exc:
            with self._lock:
                self._fail(rec, token, ErrorCode.INTERNAL_ERROR,
                           f"对比计算失败: {exc}")
            return

        with self._lock:
            cur = self._store.get_compare(compare_id)
            if (cur is None or cur.status is not TaskStatus.RUNNING
                    or cur.attempts != token):
                return  # 计算期间被取消/超时/重试，丢弃过期结论
            cur.status = TaskStatus.SUCCEEDED
            cur.result = result
            cur.error_code = None
            cur.error_detail = None
            cur.updated_at = time.time()
            self._store.upsert_compare(cur)

    # ---------- 公共 API ----------

    def submit_compare(
        self, files: list[tuple[str, bytes]], baseline_task_id: str
    ) -> CompareRecord:
        """提交版本对比；相同 (新版本, 基线) 任意并发时序只产生一条对比记录。

        基线不存在 / 未完成 / 与当前提交不同源时在入队前以可区分失败码拒绝，
        不降级为单版本审计，也不产生半成品。
        """
        sources, current_fp, baseline = self._validate(files, baseline_task_id)

        # 创建/复用新版本的普通审计任务（内部自带去重与并发互斥）
        current_task = self._tasks.submit(files)

        now = time.time()
        with self._lock:
            pair = (current_fp, baseline_task_id)
            existing_id = self._index.get(pair)
            if existing_id is not None:
                existing = self._store.get_compare(existing_id)
                if existing is not None:
                    return existing
            existing = self._store.get_compare_by_pair(current_fp, baseline_task_id)
            if existing is not None:
                self._index[pair] = existing.compare_id
                return existing

            rec = CompareRecord(
                compare_id=uuid.uuid4().hex,
                current_fingerprint=current_fp,
                baseline_task_id=baseline_task_id,
                current_task_id=current_task.task_id,
                status=TaskStatus.QUEUED,
                created_at=now,
                updated_at=now,
            )
            self._store.upsert_compare(rec)
            self._index[pair] = rec.compare_id
            self._enqueue(rec.compare_id)
            return rec

    def get(self, compare_id: str) -> CompareRecord | None:
        with self._lock:
            return self._store.get_compare(compare_id)

    def wait_for(self, compare_id: str, poll: float = 0.01,
                 deadline: float = 10.0) -> CompareRecord | None:
        end = time.time() + deadline
        while time.time() < end:
            rec = self.get(compare_id)
            if rec is not None and rec.status in _TERMINAL:
                return rec
            time.sleep(poll)
        return self.get(compare_id)

    def cancel(self, compare_id: str) -> CompareRecord | None:
        with self._lock:
            rec = self._store.get_compare(compare_id)
            if rec is None:
                return None
            if rec.status in _RUNNABLE_STATES:
                rec.status = TaskStatus.CANCELLED
                rec.error_code = ErrorCode.TASK_CANCELLED.value
                rec.error_detail = "对比任务被客户端取消"
                rec.updated_at = time.time()
                self._store.upsert_compare(rec)
            return rec

    def retry(self, compare_id: str) -> CompareRecord | None:
        with self._lock:
            rec = self._store.get_compare(compare_id)
            if rec is None:
                return None
            if rec.status not in _RETRIABLE_STATES:
                return rec
            if rec.attempts >= self._max_attempts:
                raise RuntimeError(
                    f"对比任务已达到最大尝试次数 {self._max_attempts}，拒绝重试"
                )
            rec.status = TaskStatus.QUEUED
            rec.error_code = None
            rec.error_detail = None
            rec.updated_at = time.time()
            self._store.upsert_compare(rec)
            self._enqueue(rec.compare_id)
            return rec

    def recover(self) -> list[CompareRecord]:
        """重启后恢复未完成对比任务：RUNNING 视为未完成并重新入队。"""
        records = self._store.recover_unfinished_comparisons()
        with self._lock:
            for rec in records:
                self._index[
                    (rec.current_fingerprint, rec.baseline_task_id)
                ] = rec.compare_id
                rec.status = TaskStatus.QUEUED
                rec.error_code = None
                rec.error_detail = None
                rec.updated_at = time.time()
                self._store.upsert_compare(rec)
                self._enqueue(rec.compare_id)
        return records

    def shutdown(self) -> None:
        self._runner.shutdown(wait=False, cancel_futures=True)
        self._watcher.shutdown(wait=False, cancel_futures=True)
