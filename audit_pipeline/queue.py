"""线程安全的内存任务队列。

关键设计：claim 采用"等待 -> 在锁内弹出"的标准条件变量模式，notify 只会
在有等待者时丢失于等待者尚未进入 wait 之前；这里通过 *始终在持锁状态下
决策并在循环里重判谓词* 来避免丢失唤醒：

- 谓词 = deque 非空 或 队列关闭；
- claim 持锁期间，enqueue 不可能穿插，因此“先 notify 后 wait”的丢信号
  时序在结构上不可能发生；
- 任务状态的最终事实来源是 SQLite，队列只负责待领取顺序。
"""

from __future__ import annotations

import threading
from collections import deque


class TaskQueue:
    def __init__(self) -> None:
        self._cond = threading.Condition()
        self._waiting: deque[str] = deque()
        self._enqueued: set[str] = set()
        self._closed = False

    def enqueue(self, task_id: str) -> None:
        """入队；重复入队同一任务是幂等的，不会产生两份待办。"""
        with self._cond:
            if self._closed:
                raise RuntimeError("队列已关闭，禁止再入队")
            if task_id not in self._enqueued:
                self._waiting.append(task_id)
                self._enqueued.add(task_id)
                # notify 在持锁状态下发出，等待者要么已经在 wait 中被记录，
                # 要么尚未进入 wait —— 后者在进入 wait 前会先重判谓词
                # （deque 非空），因此不会漏。
                self._cond.notify()

    def claim(self, timeout: float | None = None) -> str | None:
        """阻塞领取一个任务；超时返回 None；队列关闭且排空后返回哨兵 ``"__QUIT__"``。"""
        with self._cond:
            if timeout is None:
                while not self._waiting and not self._closed:
                    self._cond.wait()
            else:
                deadline = _monotonic() + timeout
                while not self._waiting and not self._closed:
                    remaining = deadline - _monotonic()
                    if remaining <= 0:
                        return None
                    self._cond.wait(timeout=remaining)
            if self._waiting:
                task_id = self._waiting.popleft()
                self._enqueued.discard(task_id)
                return task_id
            if self._closed:
                return "__QUIT__"
            return None

    def cancel(self, task_id: str) -> bool:
        """取消排队中的任务；返回它是否原本在待领集合中。"""
        with self._cond:
            existed = task_id in self._enqueued
            try:
                self._waiting.remove(task_id)
            except ValueError:
                pass
            self._enqueued.discard(task_id)
            if existed:
                self._cond.notify_all()
            return existed

    def contains(self, task_id: str) -> bool:
        with self._cond:
            return task_id in self._enqueued

    def size(self) -> int:
        with self._cond:
            return len(self._waiting)

    def close(self) -> None:
        with self._cond:
            self._closed = True
            self._cond.notify_all()


def _monotonic() -> float:
    import time

    return time.monotonic()
