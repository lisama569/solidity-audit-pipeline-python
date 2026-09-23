"""审计流水线的 HTTP API（FastAPI）。

接口：
    POST /audit/tasks            提交一批本地合约（幂等去重）
    GET  /audit/tasks            列出全部任务
    GET  /audit/tasks/{id}       查询任务（含结论或可区分的失败原因）
    POST /audit/tasks/{id}/cancel   取消任务
    POST /audit/tasks/{id}/retry    重试失败/超时任务
    GET  /healthz                存活探针
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .errors import AuditError
from .models import SourceFile
from .service import AuditService


class SourceIn(BaseModel):
    path: str = Field(..., description="仓库相对路径（如 contracts/Wallet.sol）")
    content: str = Field(..., description="Solidity 文件的 UTF-8 文本内容")


class SubmitIn(BaseModel):
    entry_point: str = Field(..., description="入口合约的相对路径")
    sources: list[SourceIn] = Field(..., min_length=1)
    client_labels: list[str] = Field(default_factory=list)


def _task_json(task) -> dict[str, Any]:
    data = task.to_dict()
    return data


def create_app(service: AuditService | None = None, *, start: bool = True) -> FastAPI:
    """构造 FastAPI 应用。

    service 可注入以便测试；默认使用内存库服务。start 控制是否随应用启动
    worker（测试中可关闭以自行管理生命周期）。
    """
    app = FastAPI(title="Solidity Local Audit Pipeline", version="0.1.0")
    app.state.service = service or AuditService(":memory:", workers=2)

    if start:
        # 仅在"应用自管生命周期"时注册钩子；测试中由外部显式 start/shutdown，
        # 避免 TestClient lifespan 把外部注入的服务重复启停（会提前关闭 DB 连接）。
        @app.on_event("startup")
        def _startup() -> None:  # pragma: no cover - 与 ASGI 生命周期绑定
            app.state.service.start()

        @app.on_event("shutdown")
        def _shutdown() -> None:  # pragma: no cover
            app.state.service.shutdown()

    def _error_response(exc: AuditError, status: int) -> JSONResponse:
        return JSONResponse(status_code=status, content={"error": exc.to_dict()})

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/audit/tasks", status_code=202)
    def submit_task(body: SubmitIn) -> JSONResponse:
        svc: AuditService = app.state.service
        sources = [SourceFile(path=s.path, content=s.content) for s in body.sources]
        try:
            task, created = svc.submit(
                sources, body.entry_point, client_labels=body.client_labels
            )
        except AuditError as exc:
            # 422：来源类可区分失败（缺失/无法解析/内容非法/提交结构非法）
            return _error_response(exc, 422)
        resp = _task_json(task)
        resp["deduplicated"] = not created
        # 去重命中返回 200，新任务返回 202
        return JSONResponse(status_code=200 if not created else 202, content=resp)

    @app.get("/audit/tasks")
    def list_tasks() -> dict[str, Any]:
        svc = app.state.service
        tasks = [_task_json(t) for t in svc.list_tasks()]
        return {"tasks": tasks, "count": len(tasks)}

    @app.get("/audit/tasks/{task_id}")
    def get_task(task_id: str) -> JSONResponse:
        svc = app.state.service
        try:
            task = svc.get_task(task_id)
        except AuditError as exc:
            return _error_response(exc, 404)
        return JSONResponse(content=_task_json(task))

    @app.post("/audit/tasks/{task_id}/cancel")
    def cancel_task(task_id: str) -> JSONResponse:
        svc = app.state.service
        try:
            task = svc.cancel(task_id)
        except AuditError as exc:
            status = 404 if exc.code == "TASK_NOT_FOUND" else 409
            return _error_response(exc, status)
        return JSONResponse(content=_task_json(task))

    @app.post("/audit/tasks/{task_id}/retry")
    def retry_task(task_id: str) -> JSONResponse:
        svc = app.state.service
        try:
            task = svc.retry(task_id)
        except AuditError as exc:
            status = 404 if exc.code == "TASK_NOT_FOUND" else 409
            return _error_response(exc, status)
        return JSONResponse(content=_task_json(task))

    return app


# 供 uvicorn / ``fastapi dev`` 使用的默认应用实例（内存库）
app = create_app()
