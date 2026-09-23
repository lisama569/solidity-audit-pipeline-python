"""多源合约的接入、归一与导入解析。

职责：
1. 校验提交结构（至少包含入口文件，路径合法且唯一）；
2. 解析每个文件的 import，并在已提交来源集合内做闭包解析；
3. 解析失败按 *可区分* 的错误码拒绝：
   - SOURCE_MISSING    入口文件或被引用文件缺失；
   - UNRESOLVED_IMPORT import 路径无法映射到已提交文件；
   - INVALID_CONTENT   文件内容无法被词法/语法层接受。
不静默跳过任何文件，也不产出半成品。
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass

from .errors import (
    InvalidContentError,
    InvalidSubmissionError,
    SourceMissingError,
    UnresolvedImportError,
)
from .models import SourceFile
from .parser import SourceUnit, parse_source

_ALLOWED_FIRST = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-/")


def normalize_path(raw: str) -> str:
    """归一化类 Unix 相对路径。

    - 只接受正斜杠相对路径，禁止盘符、反斜杠与 ``..`` 越界；
    - 使用 posixpath.normpath 折叠 ``./`` 与重复分隔符。
    """
    if not isinstance(raw, str) or not raw.strip():
        raise InvalidSubmissionError("路径为空或非字符串", details={"path": str(raw)})
    path = raw.strip()
    if path.startswith("/"):
        raise InvalidSubmissionError("只接受相对路径，不允许绝对路径", details={"path": raw})
    if "\\" in path or ":" in path:
        raise InvalidSubmissionError("路径包含非法的反斜杠或盘符", details={"path": raw})
    if path in (".", "..", ""):
        raise InvalidSubmissionError("路径不合法", details={"path": raw})
    if any(ch not in _ALLOWED_FIRST for ch in path):
        raise InvalidSubmissionError("路径包含非法字符", details={"path": raw})
    normalized = posixpath.normpath(path)
    if normalized.startswith("../") or normalized == ".." or normalized.startswith("/"):
        raise InvalidSubmissionError("路径越出提交根目录", details={"path": raw})
    if normalized == "." or normalized.endswith("/"):
        raise InvalidSubmissionError("路径必须指向具体文件", details={"path": raw})
    return normalized


@dataclass
class ResolvedProject:
    """归一后的合约集合。

    - sources:   归一化路径 -> 文件内容（全部已提交文件）；
    - units:     归一化路径 -> 解析后的 SourceUnit；
    - entry:     入口文件归一化路径；
    - reachable: 从入口沿 import 闭包可达的全部文件；
    - order:     依赖在前的稳定拓扑顺序。
    """

    sources: dict[str, str]
    units: dict[str, SourceUnit]
    entry: str
    reachable: list[str]
    order: list[str]


def _resolve_import_path(importer: str, spec: str) -> str:
    """把 import 路径说明映射到归一化的仓库相对路径（只支持显式相对路径）。

    无法映射（裸包名、空、路径越界）抛 UNRESOLVED_IMPORT；
    映射成功但文件不存在由调用方抛 SOURCE_MISSING。
    """
    if not spec:
        raise UnresolvedImportError(
            "import 路径为空", details={"importer": importer, "spec": spec}
        )
    # 仅支持 ./ ../ 形式的显式相对导入；裸包名（如 openzeppelin）一律视为无法解析
    if not (spec.startswith("./") or spec.startswith("../")):
        raise UnresolvedImportError(
            "只支持显式相对路径导入，裸包名无法在本地来源集合中解析",
            details={"importer": importer, "spec": spec},
        )
    base = posixpath.dirname(importer)
    joined = posixpath.normpath(posixpath.join(base, spec))
    if joined.startswith("../") or joined == "..":
        raise UnresolvedImportError(
            "import 路径越出提交根目录",
            details={"importer": importer, "spec": spec, "resolved_as": joined},
        )
    return joined


def resolve_project(sources: list[SourceFile], entry_point: str) -> ResolvedProject:
    """校验来源并解析完整依赖闭包。任何异常都以明确错误码整体拒绝。"""
    if not sources:
        raise InvalidSubmissionError("提交的来源集合为空")
    entry = normalize_path(entry_point)

    # 路径归一化 + 重复检测
    by_path: dict[str, str] = {}
    for sf in sources:
        if not isinstance(sf, SourceFile):
            raise InvalidSubmissionError("来源项必须是 SourceFile")
        if not isinstance(sf.content, str):
            raise InvalidContentError(
                "文件内容必须是 UTF-8 字符串", details={"path": sf.path}
            )
        path = normalize_path(sf.path)
        if path in by_path:
            raise InvalidSubmissionError(
                "提交中存在归一化后重复的路径", details={"path": path}
            )
        by_path[path] = sf.content

    if entry not in by_path:
        raise SourceMissingError(
            "入口合约未在提交来源中找到",
            details={"entry_point": entry, "available": sorted(by_path)},
        )

    # 语法解析全部文件（任何一个非法即整体拒绝）
    units: dict[str, SourceUnit] = {}
    for path, content in sorted(by_path.items()):
        try:
            units[path] = parse_source(path, content)
        except InvalidContentError as exc:
            # 补充文件定位信息后向上抛，保持错误码可区分
            raise InvalidContentError(
                f"文件 {path} 内容非法: {exc.message}",
                details={"path": path, **exc.details},
            ) from exc

    # import 闭包解析（从入口 BFS），按文件、行号顺序处理以保证可复现
    reachable: list[str] = []
    seen: set[str] = set()
    queue: list[str] = [entry]
    pending: set[str] = {entry}
    while queue:
        current = queue.pop(0)
        if current in seen:
            continue
        seen.add(current)
        pending.discard(current)
        reachable.append(current)

        imports = sorted(units[current].imports, key=lambda d: (d.line, d.path))
        for directive in imports:
            target = _resolve_import_path(current, directive.path)
            if target not in by_path:
                raise SourceMissingError(
                    f"被导入文件 {target} 未在提交来源中提供",
                    details={
                        "importer": current,
                        "import_spec": directive.path,
                        "resolved_as": target,
                        "line": directive.line,
                    },
                )
            if target not in seen and target not in pending:
                pending.add(target)
                queue.append(target)

    # 稳定拓扑顺序：被依赖者在前（Kahn，按名称排序入队）
    deps: dict[str, list[str]] = {p: [] for p in reachable}
    for p in reachable:
        for d in units[p].imports:
            t = _resolve_import_path(p, d.path)
            if t in deps and t not in deps[p]:
                deps[p].append(t)
    dependents: dict[str, set[str]] = {p: set() for p in reachable}
    for p, ds in deps.items():
        for d in ds:
            dependents[d].add(p)
    ready = sorted(p for p in reachable if not deps[p])
    order: list[str] = []
    remaining = {p: set(ds) for p, ds in deps.items()}
    while ready:
        node = ready.pop(0)
        order.append(node)
        for dep_of in sorted(dependents[node]):
            remaining[dep_of].discard(node)
            if not remaining[dep_of] and dep_of not in order and dep_of not in ready:
                ready.append(dep_of)
                ready.sort()
    if len(order) != len(reachable):
        # 正常情况下不会发生：import 同一文件系统不应出现环，仍明确拒绝而非静默
        raise UnresolvedImportError(
            "导入图中存在环",
            details={"files": sorted(set(reachable) - set(order))},
        )

    return ResolvedProject(
        sources=by_path,
        units=units,
        entry=entry,
        reachable=sorted(reachable),
        order=order,
    )
