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

from app import diffing, engine
from app.errors import BaselineError
from app.ingest import decode_sources, fingerprint, normalize_sources, resolve_imports
from app.models import (
    AuditReport,
    DiffReport,
    ErrorCode,
    TaskRecord,
    TaskStatus,
)
from app.store import TaskStore

_RETRIABLE_STATES = frozenset(
    {TaskStatus.FAILED, TaskStatus.TIMEOUT, TaskStatus.CANCELLED}
)
_RUNNABLE_STATES = frozenset({TaskStatus.QUEUED, TaskStatus.RUNNING})


def _finding_dict(f) -> dict:
    return {
        "finding_id": f.finding_id,
        "rule_ids": list(f.rule_ids),
        "severity": f.severity.name,
        "file": f.file,
        "line": f.line,
        "contract": f.contract,
        "function": f.function,
        "message": f.message,
        "signature": f.signature,
    }


def _report_to_dict(report: AuditReport) -> dict:
    return {
        "fingerprint": report.fingerprint,
        "clean": report.clean,
        "report_hash": report.report_hash,
        "findings": [_finding_dict(f) for f in report.findings],
    }


def _diff_to_dict(diff: DiffReport) -> dict:
    return {
        "diff_id": diff.diff_id,
        "current_fingerprint": diff.current_fingerprint,
        "baseline_fingerprint": diff.baseline_fingerprint,
        "baseline_task_id": diff.baseline_task_id,
        "current_report_hash": diff.current_report_hash,
        "baseline_report_hash": diff.baseline_report_hash,
        "diff_hash": diff.diff_hash,
        "counts": diff.counts,
        "entries": [
            {
                "category": e.category.value,
                "signature": e.signature,
                "rule_ids": list(e.rule_ids),
                "baseline_severity": (
                    e.baseline_severity.name if e.baseline_severity else None
                ),
                "current_severity": (
                    e.current_severity.name if e.current_severity else None
                ),
                "baseline_finding": (
                    _finding_dict(e.baseline_finding)
                    if e.baseline_finding is not None else None
                ),
                "current_finding": (
                    _finding_dict(e.current_finding)
                    if e.current_finding is not None else None
                ),
            }
            for e in diff.entries
        ],
    }


def record_to_dict(rec: TaskRecord) -> dict:
    """把任务记录序列化为稳定的 JSON 结构。"""
    d: dict = {
        "task_id": rec.task_id,
        "fingerprint": rec.fingerprint,
        "kind": rec.kind,
        "status": rec.status.value,
        "attempts": rec.attempts,
        "error_code": rec.error_code,
        "error_detail": rec.error_detail,
        "created_at": rec.created_at,
        "updated_at": rec.updated_at,
    }
    if rec.report is not None:
        d["report"] = _report_to_dict(rec.report)
    if rec.kind == "diff":
        d["baseline_task_id"] = rec.baseline_task_id
        d["baseline_fingerprint"] = rec.baseline_fingerprint
    if rec.diff is not None:
        d["diff"] = _diff_to_dict(rec.diff)
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
        self._diff_index: dict[tuple[str, str], str] = store.diff_pair_index()
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
            kind = rec.kind
            fp = rec.fingerprint
            base_fp = rec.baseline_fingerprint
            base_task_id = rec.baseline_task_id
            self._store.upsert(rec)

        if kind == "diff":
            result, label = self._compute_diff(
                task_id, fp, base_fp, base_task_id
            )
        else:
            result, label = self._compute_audit(fp)

        # 计算失败 -> FAILED（可重试），CAS 校验令牌
        if isinstance(result, Exception):
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
                cur.error_detail = f"{label}执行失败: {result}"
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
                return  # 执行期间被取消/超时/重试，丢弃过期结果
            cur.status = TaskStatus.SUCCEEDED
            cur.error_code = None
            cur.error_detail = None
            cur.updated_at = time.time()
            if kind == "diff":
                cur.diff = result
                self._store.save_diff(result)
            else:
                cur.report = result
                self._store.save_report(fp, result)
            self._store.upsert(cur)

    # ---------- 内部：实际计算（锁外，可安全重试） ----------

    @staticmethod
    def _audit_from_fingerprint(fp: str, files) -> AuditReport:
        sources = normalize_sources(decode_sources(files or []))
        return engine.audit(fp, sources, resolve_imports(sources))

    def _compute_audit(self, fp: str) -> tuple[object, str]:
        try:
            files = self._store.load_input(fp)
            return self._audit_from_fingerprint(fp, files), "审计"
        except Exception as exc:
            return exc, "审计"

    def _compute_diff(
        self,
        task_id: str,
        current_fp: str,
        baseline_fp: str | None,
        baseline_task_id: str | None,
    ) -> tuple[object, str]:
        try:
            cur_report = self._store.load_report(current_fp)
            if cur_report is None:
                # 新版本结论尚未就绪：现算（输入已随提交落库）
                cur_files = self._store.load_input(current_fp)
                cur_report = self._audit_from_fingerprint(current_fp, cur_files)
                self._store.save_report(current_fp, cur_report)
            base_report = self._store.load_report(baseline_fp) if baseline_fp else None
            if base_report is None:
                raise RuntimeError("基线审计结论缺失，无法对比")
            cur_files = self._store.load_input(current_fp) or []
            base_files = self._store.load_input(baseline_fp) or []
            cur_sources = normalize_sources(decode_sources(cur_files))
            base_sources = normalize_sources(decode_sources(base_files))
            cur_sigs = diffing.compute_site_signatures(
                cur_sources, resolve_imports(cur_sources)
            )
            base_sigs = diffing.compute_site_signatures(
                base_sources, resolve_imports(base_sources)
            )
            return (
                diffing.compare_reports(
                    cur_report, base_report, baseline_task_id or "",
                    cur_sigs, base_sigs,
                ),
                "版本对比",
            )
        except Exception as exc:
            return exc, "版本对比"

    # ---------- 公共 API ----------

    def submit(self, files: list[tuple[str, bytes]]) -> TaskRecord:
        """提交审计任务；相同内容（任意并发时序）返回同一任务，不重复计算。

        接入失败（来源缺失/导入不可解析/内容非法）直接抛 IngestError，
        不会创建任何任务或半成品结论。
        """
        # 先做完整校验，任何失败都在入队之前拒绝
        sources = normalize_sources(decode_sources(files))
        resolve_imports(sources)  # 仅做导入闭包校验，非法时抛 IngestError
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
                    kind="audit",
                    status=TaskStatus.SUCCEEDED,
                    report=cached,
                    created_at=now,
                    updated_at=now,
                )
            else:
                rec = TaskRecord(
                    task_id=task_id,
                    fingerprint=fp,
                    kind="audit",
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

    def submit_diff(
        self, files: list[tuple[str, bytes]], baseline_task_id: str
    ) -> TaskRecord:
        """提交「新版本 vs 历史基线」对比任务。

        - 新版本本身的接入校验与普通审计一致（失败抛 IngestError，不留半成品）；
        - 基线必须存在、必须是已完成的审计任务、且与当前提交至少共享一个来源
          文件，否则抛 BaselineError（原因彼此可区分），绝不降级为单版本审计；
        - 去重键为 (新版本指纹, 基线指纹)：同一对任意并发/重复/乱序提交只产生
          一个对比任务、一份结论；不同基线各自独立，互不复用；
        - 对比任务与普通审计一样排队、可超时/取消/重试。
        """
        # 1) 新版本来源完整校验（失败在任何任务创建之前拒绝）
        sources = normalize_sources(decode_sources(files))
        resolve_imports(sources)  # 导入闭包校验，非法时抛 IngestError
        fp = fingerprint(sources)

        # 2) 基线校验（在锁内读取，三类原因明确区分）
        with self._lock:
            baseline = self._store.get(baseline_task_id)
            if baseline is None or baseline.kind != "audit":
                raise BaselineError(
                    ErrorCode.BASELINE_NOT_FOUND,
                    f"基线审计任务 {baseline_task_id!r} 不存在",
                )
            if baseline.status is not TaskStatus.SUCCEEDED or baseline.report is None:
                raise BaselineError(
                    ErrorCode.BASELINE_NOT_READY,
                    f"基线任务 {baseline_task_id!r} 尚未审计完成"
                    f"（当前状态 {baseline.status.value}）",
                )
            baseline_fp = baseline.fingerprint
            base_files = self._store.load_input(baseline_fp)
            if base_files is None:
                # 结论在但输入载荷丢失（如外部清理）：无法核对同源关系
                raise BaselineError(
                    ErrorCode.BASELINE_NOT_READY,
                    f"基线任务 {baseline_task_id!r} 的来源载荷缺失，无法对比",
                )
            base_paths = {p for p, _ in base_files}
            cur_paths = {p for p, _ in files}
            if not (base_paths & cur_paths):
                raise BaselineError(
                    ErrorCode.BASELINE_UNRELATED,
                    "基线与当前提交没有任何同路径来源文件，不属于同一套合约，"
                    "拒绝对比（不会降级为单版本审计）",
                )

            # 输入先落库，保证随后入队的 worker 一定读得到
            self._store.save_input(fp, files)

            # 3) 新版本去重入队（与普通审计共用指纹索引；若尚未提交则排队）
            existing_audit_id = self._index.get(fp)
            audit_rec: TaskRecord | None = None
            if existing_audit_id is not None:
                audit_rec = self._store.get(existing_audit_id)
            cached_audit = self._store.load_report(fp)
            if audit_rec is None and cached_audit is not None:
                # 库里有结论缓存但无任务（理论上少见）：补一个已完成审计任务
                now0 = time.time()
                audit_rec = TaskRecord(
                    task_id=uuid.uuid4().hex,
                    fingerprint=fp,
                    kind="audit",
                    status=TaskStatus.SUCCEEDED,
                    report=cached_audit,
                    created_at=now0,
                    updated_at=now0,
                )
                self._store.upsert(audit_rec)
                self._index[fp] = audit_rec.task_id
            if audit_rec is None:
                now0 = time.time()
                audit_rec = TaskRecord(
                    task_id=uuid.uuid4().hex,
                    fingerprint=fp,
                    kind="audit",
                    status=TaskStatus.QUEUED,
                    created_at=now0,
                    updated_at=now0,
                )
                self._store.upsert(audit_rec)
                self._index[fp] = audit_rec.task_id
                self._enqueue(audit_rec.task_id)

            # 4) 对比任务按 (新版本, 基线) 去重
            pair = (fp, baseline_fp)
            existing_diff_id = self._diff_index.get(pair)
            if existing_diff_id is not None:
                existing_diff = self._store.get(existing_diff_id)
                if existing_diff is not None:
                    return existing_diff
            cached_diff = self._store.load_diff(fp, baseline_fp)
            now = time.time()
            diff_id = uuid.uuid4().hex
            if cached_diff is not None and audit_rec.status is TaskStatus.SUCCEEDED:
                rec = TaskRecord(
                    task_id=diff_id,
                    fingerprint=fp,
                    kind="diff",
                    status=TaskStatus.SUCCEEDED,
                    baseline_task_id=baseline_task_id,
                    baseline_fingerprint=baseline_fp,
                    diff=cached_diff,
                    created_at=now,
                    updated_at=now,
                )
            else:
                rec = TaskRecord(
                    task_id=diff_id,
                    fingerprint=fp,
                    kind="diff",
                    status=TaskStatus.QUEUED,
                    baseline_task_id=baseline_task_id,
                    baseline_fingerprint=baseline_fp,
                    created_at=now,
                    updated_at=now,
                )
            self._store.upsert(rec)
            self._diff_index[pair] = diff_id
            if rec.status is TaskStatus.QUEUED:
                self._enqueue(diff_id)
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
