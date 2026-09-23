"""Solidity 静态审计流水线服务入口。"""
from __future__ import annotations

import os

from fastapi import FastAPI

from app.store import TaskStore
from app.tasks import TaskManager

DB_PATH = os.environ.get("AUDIT_DB_PATH", "audit.db")

store = TaskStore(DB_PATH)
manager = TaskManager(store)

app = FastAPI(title="Solidity Audit Pipeline")


@app.on_event("startup")
def _startup() -> None:
    manager.recover()


@app.on_event("shutdown")
def _shutdown() -> None:
    manager.shutdown()


@app.get("/")
def read_root() -> dict[str, str]:
    return {"service": "solidity-audit-pipeline"}


@app.post("/audits")
def submit_audit() -> dict:
    """提交审计任务（骨架）。"""
    raise NotImplementedError


@app.get("/audits/{task_id}")
def get_audit(task_id: str) -> dict:
    """查询任务状态与结论（骨架）。"""
    raise NotImplementedError


@app.post("/audits/{task_id}/cancel")
def cancel_audit(task_id: str) -> dict:
    """取消任务（骨架）。"""
    raise NotImplementedError


@app.post("/audits/{task_id}/retry")
def retry_audit(task_id: str) -> dict:
    """重试失败任务（骨架）。"""
    raise NotImplementedError
