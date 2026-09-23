"""开发入口：``uvicorn main:app`` 或 ``fastapi dev main.py``。

生产/测试中可直接使用 :func:`audit_pipeline.api.create_app` 注入持久化服务。
"""

from audit_pipeline.api import app

__all__ = ["app"]
