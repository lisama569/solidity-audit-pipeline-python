"""来源接入与归一：校验内容、解析导入、计算输入指纹。"""
from __future__ import annotations

from app.models import SourceFile


def normalize_sources(files: list[SourceFile]) -> dict[str, str]:
    """校验并归一来源，返回 {规范路径: 内容}。失败抛 IngestError。"""
    raise NotImplementedError


def resolve_imports(sources: dict[str, str]) -> list[str]:
    """解析 import 闭包，返回拓扑排序后的路径列表。失败抛 IngestError。"""
    raise NotImplementedError


def fingerprint(sources: dict[str, str]) -> str:
    """对归一后的来源集合计算内容寻址指纹（与提交顺序无关）。"""
    raise NotImplementedError
