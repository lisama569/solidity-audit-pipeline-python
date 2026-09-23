"""Solidity 词法/语法解析（零三方依赖的本地最小实现）。

只解析审计所需的结构信息：import 路径、合约/接口/库、状态变量、
函数头（可见性、修饰器）、修饰器定义以及由 token 切片构成的语句树。
不追求完整 ABI 级语法，但对无法识别或损坏的输入必须抛出明确异常。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .errors import InvalidContentError


class LexError(InvalidContentError):
    """词法错误（非法字符、未闭合字符串/注释等）。"""

    code = "INVALID_CONTENT"


class ParseError(InvalidContentError):
    """语法/结构错误。"""

    code = "INVALID_CONTENT"


@dataclass(frozen=True)
class Token:
    kind: str  # ident | number | string | punct
    text: str
    line: int
    column: int


# ---------------------------------------------------------------- 词法分析

_SINGLE_CHAR_PUNCT = set("{}()[];,.:?!~+-*/%&|^<>= ")
_MULTI_OPS = (
    ">>=", "<<=", "**=", "...", "==", "!=", "<=", ">=", "&&", "||",
    ">>", "<<", "=>", "->", "++", "--", "+=", "-=", "*=", "/=", "%=",
    "&=", "|=", "^=",
)
_TRIVIA = {" ", "\t", "\r", "\n"}


def tokenize(source: str) -> list[Token]:
    if source is None:
        raise LexError("源码内容为空")
    if len(source.encode("utf-8", errors="ignore")) == 0 and source != "":
        raise LexError("源码包含非法编码")
    if not source.strip():
        raise LexError("源码内容为空或仅含空白字符")

    tokens: list[Token] = []
    i, line, col, n = 0, 1, 1, len(source)

    def advance(count: int = 1) -> None:
        nonlocal i, line, col
        for ch in source[i : i + count]:
            i += 1
            if ch == "\n":
                line += 1
                col = 1
            else:
                col += 1

    while i < n:
        ch = source[i]

        # 空白
        if ch in _TRIVIA:
            advance()
            continue

        start_line, start_col = line, col

        # 行注释
        if ch == "/" and i + 1 < n and source[i + 1] == "/":
            while i < n and source[i] != "\n":
                advance()
            continue

        # 块注释（Solidity 允许嵌套）
        if ch == "/" and i + 1 < n and source[i + 1] == "*":
            advance(2)
            depth = 1
            while i < n and depth > 0:
                if source[i] == "/" and i + 1 < n and source[i + 1] == "*":
                    depth += 1
                    advance(2)
                elif source[i] == "*" and i + 1 < n and source[i + 1] == "/":
                    depth -= 1
                    advance(2)
                else:
                    if source[i] == "\n":
                        line += 1
                        col = 1
                        i += 1
                    else:
                        advance()
            if depth != 0:
                raise LexError(
                    "存在未闭合的块注释",
                    details={"line": start_line, "column": start_col},
                )
            continue

        # 字符串（含 hex"..." / unicode"..." 前缀，前缀先被识别为 ident）
        if ch in ('"', "'"):
            quote = ch
            advance()
            buf: list[str] = []
            closed = False
            while i < n:
                c = source[i]
                if c == "\\":
                    if i + 1 >= n:
                        raise LexError("字符串中的转义序列被截断", details={"line": line})
                    buf.append(source[i : i + 2])
                    advance(2)
                elif c == quote:
                    advance()
                    closed = True
                    break
                elif c == "\n":
                    raise LexError("字符串未闭合即换行", details={"line": start_line})
                else:
                    buf.append(c)
                    advance()
            if not closed:
                raise LexError("存在未闭合的字符串", details={"line": start_line})
            tokens.append(Token("string", quote + "".join(buf) + quote, start_line, start_col))
            continue

        # 标识符 / 关键字
        if ch.isalpha() or ch == "_" or ch == "$":
            start = i
            while i < n and (source[i].isalnum() or source[i] in "_$"):
                advance()
            tokens.append(Token("ident", source[start:i], start_line, start_col))
            continue

        # 数字
        if ch.isdigit():
            start = i
            if ch == "0" and i + 1 < n and source[i + 1] in "xX":
                advance(2)
                while i < n and (source[i] in "0123456789abcdefABCDEF_"):
                    advance()
            else:
                while i < n and (source[i].isdigit() or source[i] in "_.eE"):
                    advance()
            tokens.append(Token("number", source[start:i], start_line, start_col))
            continue

        # 运算符与标点
        matched = None
        for op in _MULTI_OPS:
            if source.startswith(op, i):
                matched = op
                break
        if matched is None:
            if ch in "{}()[];,.:?~+-*/%&|^<>=!":
                matched = ch
            else:
                raise LexError(
                    f"无法识别的字符 {ch!r}",
                    details={"line": start_line, "column": start_col},
                )
        advance(len(matched))
        tokens.append(Token("punct", matched, start_line, start_col))

    return tokens


# ---------------------------------------------------------------- 语法结构


@dataclass
class Stmt:
    """轻量语句节点：kind 为 block/if/loop/simple/return，携带 token 切片。"""

    kind: str
    line: int
    tokens: list[Token] = field(default_factory=list)
    children: list["Stmt"] = field(default_factory=list)
    condition: list[Token] = field(default_factory=list)


@dataclass
class ModifierApp:
    name: str
    line: int


@dataclass
class Function:
    name: str  # 普通函数名；constructor/fallback/receive 使用保留名
    kind: str  # function | constructor | fallback | receive
    visibility: str  # public/external/internal/private，缺省 internal
    parameters: list[str]
    modifiers: list[ModifierApp]
    body: Stmt | None
    line: int
    local_vars: list[str] = field(default_factory=list)


@dataclass
class ModifierDef:
    name: str
    parameters: list[str]
    body: Stmt
    line: int


@dataclass
class StateVar:
    name: str
    type_name: str
    is_constant: bool
    is_immutable: bool
    line: int


@dataclass
class Contract:
    name: str
    kind: str  # contract | abstract | interface | library
    bases: list[str]
    state_vars: list[StateVar]
    functions: list[Function]
    modifier_defs: list[ModifierDef]
    line: int


@dataclass
class ImportDirective:
    path: str
    line: int


@dataclass
class SourceUnit:
    path: str
    imports: list[ImportDirective]
    contracts: list[Contract]


# ---------------------------------------------------------------- 语句构建


def _find_matching(tokens: list[Token], start: int, open_: str, close: str) -> int:
    """返回与 tokens[start]（应为 open_）配对的 close 的下标，找不到返回 -1。"""
    depth = 0
    for j in range(start, len(tokens)):
        if tokens[j].kind == "punct" and tokens[j].text == open_:
            depth += 1
        elif tokens[j].kind == "punct" and tokens[j].text == close:
            depth -= 1
            if depth == 0:
                return j
    return -1


def _build_statements(tokens: list[Token]) -> list[Stmt]:
    stmts: list[Stmt] = []
    i, n = 0, len(tokens)
    while i < n:
        t = tokens[i]

        if t.kind == "punct" and t.text == ";":
            i += 1
            continue

        if t.kind == "punct" and t.text == "{":
            end = _find_matching(tokens, i, "{", "}")
            if end == -1:
                raise ParseError("语句块缺少匹配的 }", details={"line": t.line})
            stmts.append(
                Stmt(
                    kind="block",
                    line=t.line,
                    children=_build_statements(tokens[i + 1 : end]),
                )
            )
            i = end + 1
            continue

        if t.kind == "ident" and t.text in ("if", "while", "for"):
            cond_start = i + 1
        else:
            cond_start = None

        if cond_start is not None:
            if tokens[cond_start].text != "(":
                raise ParseError(f"{t.text} 后缺少条件括号", details={"line": t.line})
            cond_end = _find_matching(tokens, cond_start, "(", ")")
            if cond_end == -1:
                raise ParseError("条件括号未闭合", details={"line": t.line})
            body_tokens = tokens[cond_end + 1 :]
            body_stmts = _build_statements(body_tokens[: _body_span(body_tokens)])
            node = Stmt(
                kind="if" if t.text == "if" else "loop",
                line=t.line,
                condition=tokens[cond_start + 1 : cond_end],
                children=body_stmts,
            )
            stmts.append(node)
            # 计算消费长度
            consumed = cond_end + 1 - i + _body_span(body_tokens)
            rest = body_tokens[_body_span(body_tokens) :]
            if t.text == "if" and rest and rest[0].text == "else":
                # else 紧随其后；解析 else 体并并入节点（额外 children 项带标记）
                else_body = _build_statements(rest[1:])
                node.children.append(Stmt(kind="else", line=rest[0].line, children=else_body))
                consumed = len(tokens) - i
            i += consumed
            continue

        # 普通语句：扫描到顶层 ; 为止
        end = i
        depth = 0
        while end < n:
            tk = tokens[end]
            if tk.text in {"(", "[", "{"}:
                depth += 1
            elif tk.text in {")", "]", "}"}:
                depth -= 1
            elif tk.text == ";" and depth == 0:
                break
            end += 1
        if end >= n:
            raise ParseError("语句缺少结束分号", details={"line": t.line})
        kind = "return" if t.kind == "ident" and t.text == "return" else "simple"
        stmts.append(Stmt(kind=kind, line=t.line, tokens=tokens[i:end]))
        i = end + 1

    return stmts


def _body_span(tokens: list[Token]) -> int:
    """从 tokens 开头解析一个语句，返回其占用的 token 数。"""
    if not tokens:
        return 0
    if tokens[0].text == "{":
        end = _find_matching(tokens, 0, "{", "}")
        return end + 1 if end != -1 else len(tokens)
    depth = 0
    for j, tk in enumerate(tokens):
        if tk.text in {"(", "[", "{"}:
            depth += 1
        elif tk.text in {")", "]", "}"}:
            depth -= 1
        elif tk.text == ";" and depth == 0:
            return j + 1
    return len(tokens)


# ---------------------------------------------------------------- 合约解析

_FUNC_KINDS = {"function", "constructor", "fallback", "receive"}
_VISIBILITY = {"public", "external", "internal", "private"}
_MUTABILITY = {"view", "pure", "payable", "virtual", "override", "constant"}


def _parse_parameter_names(tokens: list[Token]) -> list[str]:
    """从参数 token 列表中抽取参数名（最后一个 ident，若无名字则跳过）。"""
    names: list[str] = []
    pending_type = True
    idx = 0
    depth = 0
    while idx < len(tokens):
        tk = tokens[idx]
        if tk.text in {"(", "["}:
            depth += 1
        elif tk.text in {")", "]"}:
            depth -= 1
        elif tk.text == "," and depth == 0:
            pending_type = True
        elif depth == 0 and pending_type and tk.kind == "ident":
            # 形如 typeName [location] name：名字为顶层最后一个 ident
            # 向后查找到逗号/结束前的最后一个 ident
            j = idx
            last_ident = None
            d = 0
            while j < len(tokens):
                x = tokens[j]
                if x.text in {"(", "["}:
                    d += 1
                elif x.text in {")", "]"}:
                    d -= 1
                elif x.text == "," and d == 0:
                    break
                elif d == 0 and x.kind == "ident" and x.text not in (
                    "memory",
                    "calldata",
                    "storage",
                ):
                    last_ident = x.text
                j += 1
            if last_ident is not None:
                names.append(last_ident)
            return names + _parse_parameter_names(tokens[j + 1 :])
        idx += 1
    return names


def _collect_local_vars(stmts: list[Stmt], params: list[str]) -> list[str]:
    """收集函数体内声明的局部变量名（用于区分外部目标与本地变量）。"""
    locals_ = list(params)

    def walk(node: Stmt) -> None:
        for child in node.children:
            walk(child)
        toks = node.tokens
        if node.kind != "simple" or not toks:
            return
        # 顶层 '=' 之前，紧邻 '=' 的 ident 视为被声明变量（含元组）
        depth = 0
        eq_idx = -1
        for j, tk in enumerate(toks):
            if tk.text in {"(", "[", "{"}:
                depth += 1
            elif tk.text in {")", "]", "}"}:
                depth -= 1
            elif tk.text == "=" and depth == 0:
                eq_idx = j
                break
        if eq_idx == -1:
            return
        # (type a, type b) = ... 形式
        if toks[0].text == "(":
            close = _find_matching(toks, 0, "(", ")")
            inner = toks[1:close] if close != -1 else []
            d = 0
            last_ident: str | None = None
            for x in inner:
                if x.text in {"(", "["}:
                    d += 1
                elif x.text in {")", "]"}:
                    d -= 1
                elif x.text == "," and d == 0:
                    if last_ident:
                        locals_.append(last_ident)
                    last_ident = None
                elif d == 0 and x.kind == "ident" and x.text not in (
                    "memory",
                    "calldata",
                    "storage",
                ):
                    last_ident = x.text
            if last_ident:
                locals_.append(last_ident)
            return
        # type name = ... 形式：取 '=' 前最后一个 ident
        for tk in reversed(toks[:eq_idx]):
            if tk.kind == "ident":
                locals_.append(tk.text)
                break

    for s in stmts:
        walk(s)
    return locals_


def _parse_function(tokens: list[Token], start: int) -> tuple[Function, int]:
    head_kw = tokens[start]
    kind = head_kw.text
    idx = start + 1
    name = kind
    if kind == "function":
        if idx >= len(tokens) or tokens[idx].kind != "ident":
            raise ParseError("function 缺少名称", details={"line": head_kw.line})
        name = tokens[idx].text
        idx += 1

    params: list[str] = []
    if idx < len(tokens) and tokens[idx].text == "(":
        end = _find_matching(tokens, idx, "(", ")")
        if end == -1:
            raise ParseError("参数列表未闭合", details={"line": head_kw.line})
        params = _parse_parameter_names(tokens[idx + 1 : end])
        idx = end + 1

    visibility = "internal"
    modifiers: list[ModifierApp] = []
    while idx < len(tokens) and tokens[idx].text not in ("{", ";"):
        tk = tokens[idx]
        if tk.kind == "punct" and tk.text == "(":
            end = _find_matching(tokens, idx, "(", ")")
            if end == -1:
                raise ParseError("修饰器参数未闭合", details={"line": tk.line})
            idx = end + 1
        elif tk.kind == "ident" and tk.text in _VISIBILITY:
            visibility = tk.text
            idx += 1
        elif tk.kind == "ident" and tk.text in _MUTABILITY:
            idx += 1
            if tk.text == "override" and idx < len(tokens) and tokens[idx].text == "(":
                end = _find_matching(tokens, idx, "(", ")")
                idx = end + 1 if end != -1 else idx + 1
        elif tk.kind == "ident" and tk.text == "returns":
            idx += 1
            if idx < len(tokens) and tokens[idx].text == "(":
                end = _find_matching(tokens, idx, "(", ")")
                idx = end + 1 if end != -1 else idx + 1
        elif tk.kind == "ident":
            modifiers.append(ModifierApp(tk.text, tk.line))
            idx += 1
            if idx < len(tokens) and tokens[idx].text == "(":
                end = _find_matching(tokens, idx, "(", ")")
                idx = end + 1 if end != -1 else idx + 1
        else:
            idx += 1

    body: Stmt | None = None
    if idx < len(tokens) and tokens[idx].text == "{":
        end = _find_matching(tokens, idx, "{", "}")
        if end == -1:
            raise ParseError("函数体缺少 }", details={"line": head_kw.line})
        inner = tokens[idx + 1 : end]
        stmts = _build_statements(inner)
        body = Stmt(kind="block", line=tokens[idx].line, children=stmts)
        idx = end + 1
    else:
        idx += 1  # 跳过 ';'
    fn = Function(
        name=name,
        kind=kind,
        visibility=visibility,
        parameters=params,
        modifiers=modifiers,
        body=body,
        line=head_kw.line,
        local_vars=_collect_local_vars(body.children, params) if body else list(params),
    )
    return fn, idx


def _parse_modifier_def(tokens: list[Token], start: int) -> tuple[ModifierDef, int]:
    head = tokens[start]
    idx = start + 1
    if idx >= len(tokens) or tokens[idx].kind != "ident":
        raise ParseError("modifier 缺少名称", details={"line": head.line})
    name = tokens[idx].text
    idx += 1
    params: list[str] = []
    if idx < len(tokens) and tokens[idx].text == "(":
        end = _find_matching(tokens, idx, "(", ")")
        params = _parse_parameter_names(tokens[idx + 1 : end]) if end != -1 else []
        idx = end + 1 if end != -1 else idx + 1
    if idx >= len(tokens) or tokens[idx].text != "{":
        raise ParseError("modifier 缺少函数体", details={"line": head.line})
    end = _find_matching(tokens, idx, "{", "}")
    if end == -1:
        raise ParseError("modifier 函数体缺少 }", details={"line": head.line})
    body = Stmt(
        kind="block",
        line=tokens[idx].line,
        children=_build_statements(tokens[idx + 1 : end]),
    )
    return ModifierDef(name=name, parameters=params, body=body, line=head.line), end + 1


def _parse_contract(tokens: list[Token], start: int) -> tuple[Contract, int]:
    idx = start
    kind = "contract"
    if tokens[idx].text == "abstract":
        kind = "abstract"
        idx += 1
    # idx 指向 contract/interface/library
    kind = tokens[idx].text if kind == "contract" else kind
    idx += 1
    if idx >= len(tokens) or tokens[idx].kind != "ident":
        raise ParseError("合约定义缺少名称", details={"line": tokens[start].line})
    name = tokens[idx].text
    idx += 1

    bases: list[str] = []
    if idx < len(tokens) and tokens[idx].text == "is":
        idx += 1
        depth = 0
        while idx < len(tokens) and (depth > 0 or tokens[idx].text != "{"):
            tk = tokens[idx]
            if tk.text == "(":
                depth += 1
            elif tk.text == ")":
                depth -= 1
            elif depth == 0 and tk.kind == "ident":
                bases.append(tk.text)
            idx += 1

    if idx >= len(tokens) or tokens[idx].text != "{":
        raise ParseError(f"合约 {name} 缺少函数体", details={"line": tokens[start].line})
    body_start = idx
    end = _find_matching(tokens, idx, "{", "}")
    if end == -1:
        raise ParseError(f"合约 {name} 缺少 }}", details={"line": tokens[start].line})
    body = tokens[body_start + 1 : end]

    state_vars: list[StateVar] = []
    functions: list[Function] = []
    modifier_defs: list[ModifierDef] = []

    j = 0
    while j < len(body):
        tk = body[j]
        if tk.text == ";":
            j += 1
            continue
        if tk.text in ("struct", "enum", "union"):
            # 跳过带花括号的类型定义
            k = j + 1
            while k < len(body) and body[k].text != "{":
                k += 1
            if k < len(body):
                close = _find_matching(body, k, "{", "}")
                j = (close + 1) if close != -1 else len(body)
                if j < len(body) and body[j].text == ";":
                    j += 1
            else:
                j = k
            continue
        if tk.text in ("event", "error", "using", "type"):
            while j < len(body) and body[j].text != ";":
                j += 1
            j += 1
            continue
        if tk.text == "modifier" and j + 1 < len(body):
            mod, j = _parse_modifier_def(body, j)
            modifier_defs.append(mod)
            continue
        if tk.text in _FUNC_KINDS or (
            tk.text == "function"
        ):
            fn, j = _parse_function(body, j)
            functions.append(fn)
            continue
        # 其余视为状态变量/常量声明：扫描到顶层 ';'
        decl_start = j
        is_constant = False
        is_immutable = False
        type_name = tk.text if tk.kind == "ident" else ""
        terminated = False
        while j < len(body) and body[j].text != ";":
            if body[j].text == "constant":
                is_constant = True
            if body[j].text == "immutable":
                is_immutable = True
            if body[j].text in {"=", "(", "{", "["}:
                # 跳过初始化表达式/复杂类型，按配对推进
                opener = body[j].text
                closer = {"=": None, "(": ")", "{": "}", "[": "]"}[opener]
                if closer is not None:
                    close = _find_matching(body, j, opener, closer)
                    j = close if close != -1 else j
            j += 1
        if j >= len(body):
            raise ParseError(
                "状态变量声明缺少结束分号",
                details={"line": body[decl_start].line},
            )
        decl_tokens = body[decl_start:j]
        var_name = _last_top_level_ident(decl_tokens)
        if var_name is not None:
            state_vars.append(
                StateVar(
                    name=var_name,
                    type_name=type_name,
                    is_constant=is_constant,
                    is_immutable=is_immutable,
                    line=tk.line,
                )
            )
        j += 1  # 跳过 ';'

    return (
        Contract(
            name=name,
            kind=kind,
            bases=bases,
            state_vars=state_vars,
            functions=functions,
            modifier_defs=modifier_defs,
            line=tokens[start].line,
        ),
        end + 1,
    )


def _last_top_level_ident(tokens: list[Token]) -> str | None:
    """声明语句中顶层最后一个 ident，即变量名（public 等可见性关键字除外）。"""
    last: str | None = None
    depth = 0
    stop = len(tokens)
    # 初始化表达式之后不属于声明头部
    for j, tk in enumerate(tokens):
        if tk.text == "=" and depth == 0:
            stop = j
            break
        if tk.text in {"(", "[", "{"}:
            depth += 1
        elif tk.text in {")", "]", "}"}:
            depth -= 1
    for tk in tokens[:stop]:
        if tk.kind == "ident" and tk.text not in _VISIBILITY | _MUTABILITY | {
            "constant",
            "immutable",
        }:
            last = tk.text
    # 若类型是 mapping(...) 等，最后一个 ident 可能在括号内，回退策略：
    # mapping(address => uint) public balances —— balances 在顶层，正常。
    return last


def parse_source(path: str, source: str) -> SourceUnit:
    """解析单个源文件，返回结构化 SourceUnit。"""
    try:
        tokens = tokenize(source)
    except InvalidContentError:
        raise
    units: list[Contract] = []
    imports: list[ImportDirective] = []
    i, n = 0, len(tokens)
    while i < n:
        t = tokens[i]
        if t.text == "pragma":
            while i < n and tokens[i].text != ";":
                i += 1
            i += 1
            continue
        if t.text == "import":
            line = t.line
            j = i + 1
            found_path: str | None = None
            while j < n and tokens[j].text != ";":
                if tokens[j].kind == "string":
                    found_path = tokens[j].text[1:-1]
                j += 1
            if j >= n:
                raise ParseError("import 语句缺少分号", details={"line": line})
            if found_path is None:
                raise ParseError("import 语句缺少路径字符串", details={"line": line})
            imports.append(ImportDirective(found_path, line))
            i = j + 1
            continue
        if t.text in ("contract", "interface", "library") or (
            t.text == "abstract" and i + 1 < n and tokens[i + 1].text == "contract"
        ):
            unit, i = _parse_contract(tokens, i)
            units.append(unit)
            continue
        if t.text == "using":
            while i < n and tokens[i].text != ";":
                i += 1
            i += 1
            continue
        if t.text == ";" or t.text == "}":
            i += 1
            continue
        raise ParseError(
            f"文件顶层出现无法识别的 token {t.text!r}",
            details={"path": path, "line": t.line},
        )
    return SourceUnit(path=path, imports=imports, contracts=units)
