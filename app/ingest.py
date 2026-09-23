"""来源接入与归一：校验内容、解析导入、计算输入指纹。

失败原因彼此可区分：
- SOURCE_MISSING       提交为空，或某个声明的文件内容缺失
- IMPORT_UNRESOLVABLE  import 指向不存在的来源，或存在循环导入
- INVALID_CONTENT      路径非法、内容非 UTF-8、或不含任何 Solidity 结构
"""
from __future__ import annotations

import hashlib
import re

from app.errors import IngestError
from app.models import ErrorCode, SourceFile

_IMPORT_RE = re.compile(
    r"""import\s+(?:[^'"]*?\sfrom\s+)?["']([^"']+)["']\s*;"""
)
_SOLIDITY_HINT_RE = re.compile(
    r"\b(pragma|contract|library|interface|abstract|function|struct|enum|event|modifier|mapping)\b"
)


def decode_sources(files: list[tuple[str, bytes]]) -> list[SourceFile]:
    """把 (路径, 原始字节) 解码为 SourceFile；非 UTF-8 视为内容非法。"""
    out: list[SourceFile] = []
    for path, raw in files:
        try:
            text = raw.decode("utf-8")
        except (UnicodeDecodeError, AttributeError) as exc:
            raise IngestError(
                ErrorCode.INVALID_CONTENT, f"文件 {path!r} 不是合法 UTF-8 文本"
            ) from exc
        out.append(SourceFile(path=path, content=text))
    return out


def _normalize_path(path: str) -> str:
    """归一相对路径；拒绝绝对路径与越界遍历。"""
    p = path.replace("\\", "/").strip()
    if not p:
        raise IngestError(ErrorCode.INVALID_CONTENT, "存在空路径的来源文件")
    if p.startswith("/") or re.match(r"^[A-Za-z]:/", p):
        raise IngestError(ErrorCode.INVALID_CONTENT, f"非法的绝对路径: {path!r}")
    parts: list[str] = []
    for seg in p.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            raise IngestError(ErrorCode.INVALID_CONTENT, f"路径越界遍历: {path!r}")
        parts.append(seg)
    return "/".join(parts)


def normalize_sources(files: list[SourceFile]) -> dict[str, str]:
    """校验并归一来源，返回 {规范路径: 内容}。失败抛 IngestError。"""
    if not files:
        raise IngestError(ErrorCode.SOURCE_MISSING, "提交不包含任何来源文件")
    sources: dict[str, str] = {}
    for f in files:
        norm = _normalize_path(f.path)
        if norm in sources:
            raise IngestError(ErrorCode.INVALID_CONTENT, f"重复的来源路径: {norm!r}")
        if not f.content or not f.content.strip():
            raise IngestError(ErrorCode.SOURCE_MISSING, f"来源文件内容缺失: {norm!r}")
        if not _SOLIDITY_HINT_RE.search(f.content):
            raise IngestError(
                ErrorCode.INVALID_CONTENT,
                f"文件 {norm!r} 不含任何 Solidity 结构，内容非法",
            )
        sources[norm] = f.content
    return sources


def _resolve_import(importer: str, ref: str) -> str:
    """把 import 引用解析为归一后的逻辑路径。"""
    ref = ref.replace("\\", "/")
    if ref.startswith("./") or ref.startswith("../"):
        base = importer.rsplit("/", 1)[:-1]
        parts = base + ref.split("/")
    else:
        parts = ref.split("/")
    stack: list[str] = []
    for seg in parts:
        if seg in ("", "."):
            continue
        if seg == "..":
            if not stack:
                raise IngestError(
                    ErrorCode.IMPORT_UNRESOLVABLE,
                    f"{importer!r} 的导入 {ref!r} 越出根目录",
                )
            stack.pop()
        else:
            stack.append(seg)
    return "/".join(stack)


def resolve_imports(sources: dict[str, str]) -> list[str]:
    """解析 import 闭包，返回确定性的拓扑排序（依赖在前，同层按路径字典序）。

    导入目标不存在或存在循环导入时抛 IMPORT_UNRESOLVABLE。
    """
    deps: dict[str, list[str]] = {}
    for path in sorted(sources):
        refs = _IMPORT_RE.findall(sources[path])
        resolved: list[str] = []
        for ref in refs:
            target = _resolve_import(path, ref)
            if target not in sources:
                raise IngestError(
                    ErrorCode.IMPORT_UNRESOLVABLE,
                    f"{path!r} 导入了不存在的来源 {ref!r}",
                )
            if target != path and target not in resolved:
                resolved.append(target)
        deps[path] = resolved

    ordered: list[str] = []
    state: dict[str, int] = {}  # 0=未访问 1=访问中 2=完成

    def visit(node: str, trail: tuple[str, ...]) -> None:
        s = state.get(node, 0)
        if s == 2:
            return
        if s == 1:
            raise IngestError(
                ErrorCode.IMPORT_UNRESOLVABLE,
                f"检测到循环导入: {' -> '.join(trail + (node,))}",
            )
        state[node] = 1
        for dep in deps[node]:
            visit(dep, trail + (node,))
        state[node] = 2
        ordered.append(node)

    for path in sorted(sources):
        visit(path, ())
    return ordered


def fingerprint(sources: dict[str, str]) -> str:
    """对归一后的来源集合计算内容寻址指纹（与提交顺序无关）。"""
    h = hashlib.sha256()
    for path in sorted(sources):
        h.update(path.encode("utf-8"))
        h.update(b"\x00")
        h.update(sources[path].encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()
