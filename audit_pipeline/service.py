"""审计服务门面。

核心保证：
1. 幂等去重：以归一化内容哈希为唯一身份，相同合约重复提交直接复用已有
   任务/结论，绝不重复计算、绝不产生第二条结论；
2. 状态自洽：所有状态流转在一把服务锁内校验合法性，worker 领取、完成、
   失败、超时、取消、重试在任意并发时序下都只走合法路径；
3. 可恢复：状态全部落盘 SQLite，重启后 COMPLETED 结论立即可读，QUEUED
   任务继续排队，上次崩溃时遗留在 RUNNING 的任务回滚为 QUEUED；
4. 可解释失败：来源类错误在提交阶段同步抛出可区分错误码，执行期错误
   记录到任务 error 字段，可重试的失败按 max_attempts 自动重试。
"""

from __future__ import annotations

import threading
import time
import uuid
from typing import Callable

from .engine import AuditEngine, compute_project_hash
from .errors import (
    AuditError,
    TaskNotFoundError,
    TaskStateError,
    TaskTimeoutError,
)
from .models import SourceFile, Task, TaskState
from .queue import TaskQueue
from .resolver import resolve_project
from .store import TaskStore

# 合法状态流转表
# RUNNING -> QUEUED 表示执行失败/超时但仍有重试额度时的自动回队
_ALLOWED: dict[TaskState, frozenset[TaskState]] = {
    TaskState.QUEUED: frozenset(
        {TaskState.RUNNING, TaskState.CANCELLED}
    ),
    TaskState.RUNNING: frozenset(
        {
            TaskState.COMPLETED,
            TaskState.FAILED,
            TaskState.TIMEOUT,
            TaskState.CANCELLED,
            TaskState.QUEUED,
        }
    ),
    TaskState.FAILED: frozenset({TaskState.QUEUED, TaskState.CANCELLED}),
    TaskState.TIMEOUT: frozenset({TaskState.QUEUED, TaskState.CANCELLED}),
    TaskState.COMPLETED: frozenset(),
    TaskState.CANCELLED: frozenset(),
}


class AuditService:
    def __init__(
        self,
        db_path: str = ":memory:",
        workers: int = 2,
        task_timeout: float = 30.0,
        engine: AuditEngine | None = None,
    ) -> None:
        if workers < 1:
            raise ValueError("workers 必须 >= 1")
        self.store = TaskStore(db_path)
        self.queue = TaskQueue()
        self.engine = engine or AuditEngine()
        self.task_timeout = task_timeout
        self._workers_n = workers
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        # 正在执行的任务：task_id -> (取消事件, 运行代号)
        self._running: dict[str, tuple[threading.Event, int]] = {}
        self._epochs: dict[str, int] = {}
        self._started = False

    # ------------------------------------------------------------ 生命周期

    def start(self) -> None:
        with self._lock:
            if self._started:
                return
            self._started = True
            self._stop.clear()
            self._recover_locked()
            for idx in range(self._workers_n):
                t = threading.Thread(
                    target=self._worker_loop, name=f"audit-worker-{idx}", daemon=True
                )
                t.start()
                self._threads.append(t)

    def shutdown(self, wait: bool = True, timeout: float | None = 10.0) -> None:
        with self._lock:
            if not self._started:
                return
            self._started = False
        self._stop.set()
        self.queue.close()
        if wait:
            for t in self._threads:
                t.join(timeout=timeout)
        self._threads.clear()

    def _recover_locked(self) -> None:
        """重启恢复：RUNNING 遗留在 RUNNING 则视为上次崩溃，回滚为 QUEUED。"""
        for task in self.store.tasks_in_states(TaskState.RUNNING):
            task.state = TaskState.QUEUED
            task.started_at = None
            task.deadline = None
            self.store.save(task)
        for task in self.store.tasks_in_states(TaskState.QUEUED):
            self.queue.enqueue(task.id)

    # ------------------------------------------------------------ 提交

    def submit(
        self,
        sources: list[SourceFile],
        entry_point: str,
        *,
        client_labels: list[str] | None = None,
        max_attempts: int = 3,
    ) -> tuple[Task, bool]:
        """提交一批合约。

        - 来源非法时同步抛出 SOURCE_MISSING / UNRESOLVED_IMPORT /
          INVALID_CONTENT / INVALID_SUBMISSION，绝不产生半成品任务；
        - 相同内容（哈希一致）重复提交返回已有任务，第二个返回值为 False
          （表示"已存在/去重命中"），且不会重新排队或计算。
        """
        # 先做完整来源校验（在写任何状态之前，失败即整体拒绝）
        project = resolve_project(sources, entry_point)
        content_hash = compute_project_hash(project)
        labels = sorted(client_labels or [])

        with self._lock:
            existing = self.store.get_by_hash(content_hash)
            if existing is not None:
                return existing, False

            now = time.time()
            task = Task(
                id=f"task-{uuid.uuid4().hex}",
                content_hash=content_hash,
                state=TaskState.QUEUED,
                entry_point=entry_point,
                sources=dict(project.sources),
                max_attempts=max_attempts,
                created_at=now,
                updated_at=now,
                client_labels=labels,
            )
            self.store.save(task)
            self.queue.enqueue(task.id)
            return task, True

    # ------------------------------------------------------------ 查询/操作

    def get_task(self, task_id: str) -> Task:
        task = self.store.get(task_id)
        if task is None:
            raise TaskNotFoundError("任务不存在", details={"task_id": task_id})
        return task

    def list_tasks(self) -> list[Task]:
        return self.store.all_tasks()

    def cancel(self, task_id: str) -> Task:
        """取消任务。QUEUED 立即取消；RUNNING 请求协作取消；终态拒绝。"""
        with self._lock:
            task = self.get_task(task_id)
            if task.state in (TaskState.COMPLETED, TaskState.CANCELLED):
                raise TaskStateError(
                    "任务已处于终态，无法取消",
                    details={"task_id": task_id, "state": task.state.value},
                )
            if task.state == TaskState.QUEUED:
                self._transition_locked(task, TaskState.CANCELLED)
                self.queue.cancel(task_id)
                self.store.save(task)
                return task
            if task.state == TaskState.RUNNING:
                entry = self._running.get(task_id)
                if entry is not None:
                    entry[0].set()
                # 状态由 worker 观察到事件后在 _finish_cancelled_locked 中落盘
                return task
            # FAILED / TIMEOUT 等待重试的任务
            self._transition_locked(task, TaskState.CANCELLED)
            self.store.save(task)
            return task

    def retry(self, task_id: str) -> Task:
        """显式重试：仅 FAILED / TIMEOUT 可重试（终态/运行态拒绝）。"""
        with self._lock:
            task = self.get_task(task_id)
            if task.state not in (TaskState.FAILED, TaskState.TIMEOUT):
                raise TaskStateError(
                    "只有失败或超时的任务可以重试",
                    details={"task_id": task_id, "state": task.state.value},
                )
            task.error = None
            self._transition_locked(task, TaskState.QUEUED)
            self.store.save(task)
            self.queue.enqueue(task.id)
            return task

    def wait_for(
        self, task_id: str, timeout: float | None = None, poll: float = 0.02
    ) -> Task:
        """测试/同步客户端辅助：阻塞直到任务进入最终终态或超时。

        FAILED/TIMEOUT 仅在重试额度耗尽后才算终态；仍有额度时任务会被
        worker 自动重新排队，这里继续等待。
        """
        deadline = None if timeout is None else time.time() + timeout
        while True:
            task = self.get_task(task_id)
            if task.state in (TaskState.COMPLETED, TaskState.CANCELLED):
                return task
            if task.state in (TaskState.FAILED, TaskState.TIMEOUT):
                if task.attempts >= task.max_attempts:
                    return task
            if deadline is not None and time.time() >= deadline:
                raise TimeoutError("等待任务终态超时")
            time.sleep(poll)

    # ------------------------------------------------------------ 状态机

    def _transition_locked(self, task: Task, target: TaskState) -> None:
        allowed = _ALLOWED.get(task.state, frozenset())
        if target not in allowed:
            raise TaskStateError(
                f"非法状态流转: {task.state.value} -> {target.value}",
                details={"task_id": task.id, "from": task.state.value, "to": target.value},
            )
        task.state = target

    # ------------------------------------------------------------ worker

    def _worker_loop(self) -> None:
        while not self._stop.is_set():
            task_id = self.queue.claim(timeout=0.1)
            if task_id is None:
                continue
            if task_id == "__QUIT__":
                return
            self._run_once(task_id)

    def _run_once(self, task_id: str) -> None:
        with self._lock:
            task = self.store.get(task_id)
            if task is None:
                return
            if task.state != TaskState.QUEUED:
                return  # 可能已在等待期间被取消
            self._transition_locked(task, TaskState.RUNNING)
            task.attempts += 1
            task.started_at = time.time()
            task.deadline = task.started_at + self.task_timeout
            cancel_event = threading.Event()
            epoch = self._epochs.get(task_id, 0) + 1
            self._epochs[task_id] = epoch
            self._running[task_id] = (cancel_event, epoch)
            self.store.save(task)

        result_box: dict = {}
        err_box: dict = {}

        def target() -> None:
            try:
                sources = [SourceFile(p, c) for p, c in task.sources.items()]
                project = resolve_project(sources, task.entry_point)
                if cancel_event.is_set():
                    return
                result_box["report"] = self.engine.audit_project(project, task.content_hash)
            except Exception as exc:  # noqa: BLE001 - 需要在任务层面捕获全部失败
                err_box["error"] = exc

        worker = threading.Thread(target=target, name=f"audit-exec-{task_id[:12]}", daemon=True)
        worker.start()
        worker.join(timeout=self.task_timeout)

        with self._lock:
            # 若该任务已因超时回队并被其它 worker 以更新的代号领取，本回合失效
            current = self._running.get(task_id)
            if current is None or current[1] != epoch:
                return
            self._running.pop(task_id, None)
            # 重新读盘获取最新状态
            task = self.store.get(task_id)
            if task is None:
                return

            if cancel_event.is_set():
                self._finish_cancelled_locked(task)
                return

            if worker.is_alive():
                # 超时：执行线程仍在跑（守护线程，无法强杀），任务判超时并回队
                self._finish_timeout_locked(task, worker)
                return

            if "error" in err_box:
                self._finish_failed_locked(task, err_box["error"])
                return

            task.report = result_box["report"]
            task.error = None
            task.started_at = None
            task.deadline = None
            self._transition_locked(task, TaskState.COMPLETED)
            self.store.save(task)

    def _finish_cancelled_locked(self, task: Task) -> None:
        task.started_at = None
        task.deadline = None
        task.error = {"code": "CANCELLED", "message": "任务在执行期间被取消", "details": {}}
        self._transition_locked(task, TaskState.CANCELLED)
        self.store.save(task)

    def _finish_timeout_locked(self, task: Task, thread: threading.Thread) -> None:
        task.started_at = None
        task.deadline = None
        err = TaskTimeoutError(
            f"审计执行超过 {self.task_timeout}s 时限",
            details={"task_id": task.id, "attempt": task.attempts},
        )
        task.error = err.to_dict()
        if task.attempts >= task.max_attempts or self._stop.is_set():
            self._transition_locked(task, TaskState.TIMEOUT)
            self.store.save(task)
        else:
            self._transition_locked(task, TaskState.QUEUED)
            self.store.save(task)
            self.queue.enqueue(task.id)

    def _finish_failed_locked(self, task: Task, exc: Exception) -> None:
        if isinstance(exc, AuditError):
            task.error = exc.to_dict()
        else:
            task.error = {
                "code": "INTERNAL_ERROR",
                "message": f"{type(exc).__name__}: {exc}",
                "details": {},
            }
        task.started_at = None
        task.deadline = None
        if task.attempts >= task.max_attempts or self._stop.is_set():
            self._transition_locked(task, TaskState.FAILED)
            self.store.save(task)
        else:
            self._transition_locked(task, TaskState.QUEUED)
            self.store.save(task)
            self.queue.enqueue(task.id)
