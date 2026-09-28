"""基于规则的漏洞识别：重入（含跨函数）与危险外部调用。

实现为确定性的轻量静态分析：
1. 去除注释（保留行号）；
2. 解析 contract / function / modifier 结构（花括号配对）；
3. 收集状态变量与锁（重入保护）信息；
4. 在函数体内定位外部调用与状态写，按规则产出 RawHit。

同一处问题被多条规则命中时，由 engine 层按 (file, line, function) 合并。
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from app.models import Severity


@dataclass(frozen=True)
class RawHit:
    """单条规则的原始命中（尚未归一）。"""

    rule_id: str
    severity: Severity
    file: str
    line: int
    contract: str
    function: str
    message: str
    issue_key: str = ""  # 问题稳定身份（与行号/命名/注释无关，由结构计算）


RULE_REENTRANCY = "REENTRANCY"
RULE_DANGEROUS_CALL = "DANGEROUS_EXTERNAL_CALL"

_COMMENT_RE = re.compile(r"//[^\n]*|/\*.*?\*/", re.DOTALL)
_CONTRACT_RE = re.compile(r"\b(?:contract|library|interface)\s+([A-Za-z_]\w*)[^{};]*\{")
_FUNC_RE = re.compile(
    r"\b(function|modifier)\s+([A-Za-z_]\w*)\s*\([^)]*\)\s*([^{};]*)(\{|;)"
)
_STATE_VAR_RE = re.compile(
    r"\b(?:mapping\s*\([^;]*?\)|u?int\d*|bool|address|bytes\d*|string)"
    r"(?:\s*\[\s*\])*\s+"
    r"(?:public|private|internal|constant|immutable|override|\s)*"
    r"([A-Za-z_]\w*)\s*(?:=[^;]*)?;"
)
_LOCK_NAME_RE = re.compile(r"lock|guard|mutex|entered|reentr", re.IGNORECASE)
_EXT_CALL_RE = re.compile(
    r"\.\s*(call|delegatecall|callcode|send|transfer)\s*[({]"
)

# 归一化时保留的 Solidity 关键字/内置名（其余标识符视为用户命名，统一屏蔽），
# 这样纯重命名不会改变问题身份，而结构性改动（是否 require/checked 等）会。
_RESERVED_WORDS = frozenset(
    {
        "require", "assert", "revert", "if", "else", "for", "while", "do",
        "return", "returns", "true", "false", "new", "delete", "public",
        "private", "internal", "external", "view", "pure", "payable",
        "constant", "immutable", "memory", "storage", "calldata", "this",
        "super", "msg", "tx", "block", "value", "sender", "data", "ok",
        "bool", "uint", "int", "address", "bytes", "string",
    }
)
_TOKEN_RE = re.compile(r"[A-Za-z_]\w*|\d+|0x[0-9a-fA-F]+|\".*?\"|'.*?'|\S")


def _mask_identifiers(text: str) -> str:
    """把用户标识符/数值/字符串字面量归一为 #，保留关键字与运算符结构。"""
    def repl(m: re.Match[str]) -> str:
        tok = m.group(0)
        if tok[0].isalpha() or tok[0] == "_":
            return tok if tok in _RESERVED_WORDS else "#"
        return "#"  # 数值与字符串字面量

    return _TOKEN_RE.sub(repl, text)


def _normalize_code(text: str) -> str:
    """空白折叠 + 标识符屏蔽，得到只反映结构的规范串。"""
    masked = _mask_identifiers(text)
    return re.sub(r"\s+", " ", masked).strip()


def _enclosing_statement(fn: "_Function", cm: re.Match[str]) -> str:
    """提取外部调用所在语句的源码片段（用于稳定身份）。"""
    stmt_start = max(
        fn.body.rfind(";", 0, cm.start()),
        fn.body.rfind("{", 0, cm.start()),
        fn.body.rfind("}", 0, cm.start()),
    ) + 1
    stmt_end = fn.body.find(";", cm.end())
    return fn.body[stmt_start : stmt_end if stmt_end != -1 else len(fn.body)]


def _norm_statement(fn: "_Function", cm: re.Match[str]) -> str:
    stmt = _enclosing_statement(fn, cm)
    # 身份层面把外部调用抽象为统一标记：操作码严重度差异交给分类器
    # 判为 SEVERITY_CHANGED，调用附带的 {value/gas} 与实参属于噪声。
    # 不同性质的问题（delegatecall vs 普通 call）由函数上下文中的其余
    # 结构与分类结果共同区分。
    stmt = re.sub(r"\{[^{}]*\}", "", stmt)
    stmt = re.sub(
        r"\.\s*(call|delegatecall|callcode|send|transfer)\s*\([^()]*\)",
        ".<CALL>",
        stmt,
    )
    stmt = re.sub(
        r"\.\s*(call|delegatecall|callcode|send|transfer)\b", ".<CALL>", stmt
    )
    return _normalize_code(stmt)


def _norm_write_snippets(fn: "_Function", state_vars: list[str],
                        after: int) -> list[str]:
    """外部调用之后的状态写语句规范串（直接写，用于重入身份）。"""
    out: list[str] = []
    for var in state_vars:
        for m in re.finditer(
            r"\b" + re.escape(var) + r"\b(?:\s*\[[^\]]*\])?"
            r"\s*(?:[-+*/|&^%]?=(?![=>])|\+\+|--)",
            fn.body,
        ):
            if m.start() <= after:
                continue
            stmt_end = fn.body.find(";", m.end())
            out.append(
                _normalize_code(
                    fn.body[m.start() : stmt_end if stmt_end != -1 else len(fn.body)]
                )
            )
        for m in re.finditer(r"\bdelete\s+" + re.escape(var) + r"\b", fn.body):
            if m.start() <= after:
                continue
            stmt_end = fn.body.find(";", m.end())
            out.append(
                _normalize_code(
                    fn.body[m.start() : stmt_end if stmt_end != -1 else len(fn.body)]
                )
            )
    return sorted(set(out))


def _function_context(fn: "_Function", cm: re.Match[str]) -> str:
    """函数身份：归一化函数头 + 挖空当前调用点语句后的函数体。

    调用点语句本身被挖空，因此 send->call 这类调用方式升级不会改变函数身份；
    而调用点之外的结构差异（不同函数）仍然可区分。
    """
    stmt_start = max(
        fn.body.rfind(";", 0, cm.start()),
        fn.body.rfind("{", 0, cm.start()),
        fn.body.rfind("}", 0, cm.start()),
    ) + 1
    stmt_end = fn.body.find(";", cm.end())
    end = stmt_end + 1 if stmt_end != -1 else len(fn.body)
    blanked = fn.body[:stmt_start] + " " + fn.body[end:]
    return _normalize_code(fn.header + " " + blanked)


def _dangerous_key(file: str, context: str, norm_stmt: str) -> str:
    return f"D|{file}|{context}|{norm_stmt}"


def _reentrancy_key(file: str, context: str, norm_stmt: str, writes: list[str],
                    cross: list[str]) -> str:
    return (
        f"R|{file}|{context}|{norm_stmt}|w={','.join(writes)}|c={','.join(cross)}"
    )


@dataclass
class _Function:
    name: str
    kind: str  # function | modifier
    header: str
    body: str
    body_offset: int  # 相对文件开头的偏移


@dataclass
class _Contract:
    name: str
    body: str
    body_offset: int
    functions: list["_Function"]
    state_vars: list[str]


def _strip_comments(text: str) -> str:
    """用空白替换注释，保留行号与列布局。"""
    def _blank(m: re.Match[str]) -> str:
        return re.sub(r"[^\n]", " ", m.group(0))

    return _COMMENT_RE.sub(_blank, text)


def _match_brace(text: str, open_idx: int) -> int:
    """返回与 text[open_idx]=='{' 配对的 '}' 下标。"""
    depth = 0
    for i in range(open_idx, len(text)):
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
    return len(text) - 1


def _parse_functions(body: str, body_offset: int) -> tuple[list[_Function], str]:
    """解析合约体内的函数/修改器；返回函数列表与挖掉函数体后的骨架文本。"""
    funcs: list[_Function] = []
    skeleton = list(body)
    for m in _FUNC_RE.finditer(body):
        kind, name, header, term = m.group(1), m.group(2), m.group(3), m.group(4)
        if term == ";":  # 接口声明，无函数体
            continue
        open_idx = m.end() - 1
        close_idx = _match_brace(body, open_idx)
        fbody = body[open_idx + 1 : close_idx]
        funcs.append(
            _Function(
                name=name,
                kind=kind,
                header=header,
                body=fbody,
                body_offset=body_offset + open_idx + 1,
            )
        )
        for i in range(m.start(), close_idx + 1):
            if skeleton[i] != "\n":
                skeleton[i] = " "
    return funcs, "".join(skeleton)


def _parse_contracts(text: str) -> list[_Contract]:
    contracts: list[_Contract] = []
    for m in _CONTRACT_RE.finditer(text):
        open_idx = m.end() - 1
        close_idx = _match_brace(text, open_idx)
        body = text[open_idx + 1 : close_idx]
        body_offset = open_idx + 1
        funcs, skeleton = _parse_functions(body, body_offset)
        state_vars = sorted(set(_STATE_VAR_RE.findall(skeleton)))
        contracts.append(
            _Contract(
                name=m.group(1),
                body=body,
                body_offset=body_offset,
                functions=funcs,
                state_vars=state_vars,
            )
        )
    return contracts


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _state_writes(fn: _Function, state_vars: list[str]) -> list[int]:
    """函数体内状态变量写入的位置（相对函数体）。"""
    positions: list[int] = []
    for var in state_vars:
        pat = re.compile(
            r"\b" + re.escape(var) + r"\b(?:\s*\[[^\]]*\])?"
            r"\s*(?:[-+*/|&^%]?=(?![=>])|\+\+|--)"
        )
        positions.extend(m.start() for m in pat.finditer(fn.body))
        positions.extend(
            m.start()
            for m in re.finditer(r"\bdelete\s+" + re.escape(var) + r"\b", fn.body)
        )
    return sorted(positions)


def _lock_vars(contract: _Contract) -> list[str]:
    return [v for v in contract.state_vars if _LOCK_NAME_RE.search(v)]


def _is_protected(contract: _Contract, fn: _Function) -> bool:
    """函数是否受重入锁保护：nonReentrant 类修改器或 require(!lock) 检查。"""
    lock_vars = _lock_vars(contract)
    # 1) 头部挂接了带锁语义的修改器，且该修改器体内确实设置锁变量
    for mod_name in re.findall(r"[A-Za-z_]\w*", fn.header):
        if not _LOCK_NAME_RE.search(mod_name):
            continue
        for other in contract.functions:
            if other.kind == "modifier" and other.name == mod_name:
                if any(
                    re.search(r"\b" + re.escape(v) + r"\b\s*=", other.body)
                    for v in lock_vars
                ) or _LOCK_NAME_RE.search(other.body):
                    return True
    # 2) 函数体内直接 require 检查锁变量
    for v in lock_vars:
        if re.search(
            r"\brequire\s*\(\s*!\s*" + re.escape(v) + r"\b", fn.body
        ) or re.search(
            r"\brequire\s*\(\s*" + re.escape(v) + r"\s*==", fn.body
        ):
            return True
    return False


def _internal_writers(contract: _Contract) -> dict[str, bool]:
    """每个函数是否（传递地）触发状态写。"""
    writes: dict[str, bool] = {}
    direct = {
        f.name: bool(_state_writes(f, contract.state_vars)) for f in contract.functions
    }

    def visit(name: str, seen: set[str]) -> bool:
        if name in writes:
            return writes[name]
        if name in seen or name not in direct:
            return False
        seen.add(name)
        fn = next(f for f in contract.functions if f.name == name)
        if direct[name]:
            writes[name] = True
            return True
        callees = set(re.findall(r"\b([A-Za-z_]\w*)\s*\(", fn.body)) & set(direct)
        result = any(visit(c, seen) for c in callees)
        writes[name] = result
        return result

    for f in contract.functions:
        visit(f.name, set())
    return writes


def _analyze_contract(
    file: str, text: str, contract: _Contract
) -> list[RawHit]:
    hits: list[RawHit] = []
    writers = _internal_writers(contract)
    fn_by_name = {f.name: f for f in contract.functions}

    for fn in contract.functions:
        if fn.kind != "function":
            continue
        calls = list(_EXT_CALL_RE.finditer(fn.body))
        if not calls:
            continue
        protected = _is_protected(contract, fn)

        for cm in calls:
            op = cm.group(1)
            call_line = _line_of(text, fn.body_offset + cm.start())
            norm_stmt = _norm_statement(fn, cm)
            context = _function_context(fn, cm)
            d_key = _dangerous_key(file, context, norm_stmt)

            # --- 规则：危险外部调用 ---
            if op in ("delegatecall", "callcode"):
                hits.append(
                    RawHit(
                        rule_id=RULE_DANGEROUS_CALL,
                        severity=Severity.HIGH,
                        file=file,
                        line=call_line,
                        contract=contract.name,
                        function=fn.name,
                        message=f"危险的 {op} 外部调用，可执行任意代码",
                        issue_key=d_key,
                    )
                )
            elif op == "call":
                stmt = _enclosing_statement(fn, cm)
                checked = "require" in stmt or re.search(r"\bbool\b", stmt)
                if not checked:
                    hits.append(
                        RawHit(
                            rule_id=RULE_DANGEROUS_CALL,
                            severity=Severity.MEDIUM,
                            file=file,
                            line=call_line,
                            contract=contract.name,
                            function=fn.name,
                            message="低层 call 外部调用且未检查返回值",
                            issue_key=d_key,
                        )
                    )
            elif op == "send":
                stmt = _enclosing_statement(fn, cm)
                if "require" not in stmt and not re.search(r"\bbool\b", stmt):
                    hits.append(
                        RawHit(
                            rule_id=RULE_DANGEROUS_CALL,
                            severity=Severity.LOW,
                            file=file,
                            line=call_line,
                            contract=contract.name,
                            function=fn.name,
                            message="send 返回值未检查",
                            issue_key=d_key,
                        )
                    )

            # --- 规则：重入（call 之后仍存在状态写） ---
            if protected:
                continue
            write_snips = _norm_write_snippets(fn, contract.state_vars, cm.start())
            later_write = bool(write_snips)
            cross_bodies: list[str] = []
            if not later_write:
                tail = fn.body[cm.end() :]
                for callee in re.findall(r"\b([A-Za-z_]\w*)\s*\(", tail):
                    if callee in fn_by_name and callee != fn.name and writers.get(callee):
                        cross_bodies.append(
                            _normalize_code(fn_by_name[callee].body)
                        )
            cross_bodies = sorted(set(cross_bodies))
            cross_fn = bool(cross_bodies)
            if later_write or cross_fn:
                sev = (
                    Severity.HIGH
                    if op in ("call", "delegatecall", "callcode")
                    else Severity.MEDIUM
                )
                kind = "跨函数" if cross_fn and not later_write else "函数内"
                hits.append(
                    RawHit(
                        rule_id=RULE_REENTRANCY,
                        severity=sev,
                        file=file,
                        line=call_line,
                        contract=contract.name,
                        function=fn.name,
                        message=(
                            f"外部 {op} 调用之后仍存在状态写（{kind}重入风险），"
                            "且未受重入锁保护"
                        ),
                        issue_key=_reentrancy_key(
                            file, context, norm_stmt, write_snips, cross_bodies
                        ),
                    )
                )
    return hits


def run_rules(sources: dict[str, str], ordered_paths: list[str]) -> list[RawHit]:
    """对归一后的来源运行全部规则，返回确定性排序的原始命中列表。"""
    hits: list[RawHit] = []
    for path in ordered_paths:
        text = _strip_comments(sources[path])
        for contract in _parse_contracts(text):
            hits.extend(_analyze_contract(path, text, contract))
    hits.sort(key=lambda h: (h.file, h.line, h.rule_id, h.function))
    return hits
