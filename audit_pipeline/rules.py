"""基于规则的漏洞识别。

内置规则（规则 ID 稳定，跨运行一致）：
    REENTRANCY-001          重入（同函数 / 跨函数两个变体）
    DANGEROUS-CALL-001      危险低级外部调用（call/delegatecall 等）

分析基于 parser 产出的结构信息与 token 切片，纯函数、无随机数、无环境依赖，
因此同一项目在任何时刻、任何提交顺序与并发下结论完全一致。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .models import Finding, Location, Severity
from .parser import (
    Contract,
    Function,
    ModifierDef,
    SourceUnit,
    Stmt,
    Token,
    _find_matching,
)
from .resolver import ResolvedProject

# ---------------------------------------------------------------- 常量

# 低级调用方法（最后一段标识符命中即视为低级调用）
LOW_LEVEL_METHODS = frozenset(
    {"call", "delegatecall", "staticcall", "send", "transfer"}
)
# 不转发全部 gas、语义相对安全的方法
SAFE_VALUE_METHODS = frozenset({"transfer", "send"})
KEYWORDS = frozenset(
    {
        "require", "assert", "revert", "if", "else", "while", "for", "do",
        "return", "emit", "new", "delete", "this", "super", "true", "false",
        "msg", "block", "tx", "address", "abi", "type", "unchecked",
    }
)
STATE_MUTATING = frozenset({"public", "external", "internal", "private", "view", "pure", "payable"})


class Rule(Protocol):
    id: str

    def evaluate(self, project: ResolvedProject) -> list[Finding]:
        ...


# ---------------------------------------------------------------- 语句遍历


def flatten_statements(root: Stmt) -> list[Stmt]:
    """深度优先、按源码顺序展开全部语句（含嵌套 block/if/loop 体）。"""
    out: list[Stmt] = []

    def walk(node: Stmt) -> None:
        if node.kind in ("block", "else"):
            for child in node.children:
                walk(child)
            return
        out.append(node)
        for child in node.children:
            walk(child)

    walk(root)
    return out


@dataclass
class CallInfo:
    method: str          # 最后一段方法名（call / withdraw / transfer ...）
    kind: str            # low-level | high-level
    target_expr: str     # 点链目标表达式，如 msg.sender / token
    stmt_index: int      # 所在函数语句序列下标
    line: int
    column: int
    statement: Stmt
    call_token_index: int


def extract_calls(stmt: Stmt, stmt_index: int, local_vars: set[str]) -> list[CallInfo]:
    """识别一条语句中的外部调用。

    覆盖两类形态：
      - 低级:  x.call("...") / addr.delegatecall / target.send / .transfer
      - 高级:  obj.method(args)，其中 obj 既不是本地变量也不是关键字
               （构造合约局部变量属于本地变量，不计外部入口）
    返回顺序按调用 token 位置，稳定可复现。
    """
    toks = stmt.tokens
    calls: list[CallInfo] = []
    n = len(toks)

    def paren_after(method_idx: int) -> int:
        # 方法 token 之后可紧跟 {options}，然后必须是 '('
        j = method_idx + 1
        if j < n and toks[j].text == "{":
            close = _find_matching(toks, j, "{", "}")
            if close == -1:
                return -1
            j = close + 1
        return j if j < n and toks[j].text == "(" else -1

    i = 0
    while i < n:
        tk = toks[i]
        # 方法位：前一个 token 是 '.'，再前一个是 ident
        if (
            i >= 2
            and tk.kind == "ident"
            and toks[i - 1].text == "."
            and toks[i - 2].kind == "ident"
        ):
            method = tk.text
            paren = paren_after(i)
            # 回退点链起点 a . b . c . method
            start = i - 2
            while start - 2 >= 0 and toks[start - 1].text == "." and toks[start - 2].kind == "ident":
                start -= 2
            if paren != -1 and method not in KEYWORDS:
                target_parts = [toks[start].text]
                k2 = start + 1
                while k2 + 2 <= i and toks[k2].text == ".":
                    target_parts.append(toks[k2 + 1].text)
                    k2 += 2
                target = ".".join(target_parts)
                if method in LOW_LEVEL_METHODS:
                    kind = "low-level"
                else:
                    head = toks[start].text
                    kind = "high-level" if head not in local_vars and head not in KEYWORDS else "local"
                if kind in ("low-level", "high-level"):
                    calls.append(
                        CallInfo(
                            method=method,
                            kind=kind,
                            target_expr=target,
                            stmt_index=stmt_index,
                            line=tk.line,
                            column=tk.column,
                            statement=stmt,
                            call_token_index=i,
                        )
                    )
        i += 1

    calls.sort(key=lambda c: (c.line, c.column))
    return calls


# ---------------------------------------------------------------- 状态访问


def _state_var_names(contract: Contract) -> set[str]:
    return {v.name for v in contract.state_vars if not v.is_constant}


def _top_level_assignments(toks: list[Token]) -> dict[int, str]:
    """找出顶层赋值位置 -> 赋值符（=, += 等）。"""
    result: dict[int, str] = {}
    depth = 0
    for j, tk in enumerate(toks):
        if tk.text in {"(", "[", "{"}:
            depth += 1
        elif tk.text in {")", "]", "}"}:
            depth -= 1
        elif depth == 0 and tk.kind == "punct" and (
            tk.text == "=" or (len(tk.text) == 2 and tk.text.endswith("=") and tk.text[0] in "+-*/%&|^")
        ):
            result[j] = tk.text
    return result


def _written_state_vars(stmt: Stmt, state_vars: set[str]) -> set[str]:
    """语句中在顶层被赋值的状态变量名（支持元组与映射槽写入）。"""
    toks = stmt.tokens
    writes: set[str] = set()
    depth = 0
    assign_positions = _top_level_assignments(toks)
    if not assign_positions:
        # delete x / mapping[k].f++ 等情况：保守起见也识别 delete stateVar
        for j, tk in enumerate(toks):
            if tk.text == "delete" and j + 1 < len(toks):
                nxt = toks[j + 1]
                if nxt.kind == "ident" and nxt.text in state_vars:
                    writes.add(nxt.text)
        return writes

    first_assign = min(assign_positions)
    lhs = toks[:first_assign]

    # 元组左值 (a, b) = ...
    d = 0
    tuple_mode = bool(lhs and lhs[0].text == "(")
    if tuple_mode:
        for tk in lhs:
            if tk.kind == "ident" and tk.text in state_vars:
                writes.add(tk.text)
        # mapping 槽：balances[msg.sender] 在元组内也可能出现
        d = 0
        for j, tk in enumerate(lhs):
            if tk.text in {"(", "["}:
                d += 1
            elif tk.text in {")", "]"}:
                d -= 1
            elif tk.kind == "ident" and tk.text in state_vars:
                writes.add(tk.text)
        return writes

    # 普通左值：balances[msg.sender] -= x；取第一个命中的状态变量
    for tk in lhs:
        if tk.kind == "ident" and tk.text in state_vars:
            writes.add(tk.text)
    return writes


def _read_state_vars(stmt: Stmt, state_vars: set[str], written: set[str]) -> set[str]:
    """语句中出现的状态变量读取（排除本语句写入目标）。"""
    reads: set[str] = set()
    toks = stmt.tokens
    assign_positions = _top_level_assignments(toks)
    cutoff = min(assign_positions) if assign_positions else len(toks)
    # 复合赋值右侧仍可能读状态变量；简单起见，扫描 '=' 之后部分 + LHS 中非写入变量
    rhs_start = (min(assign_positions) + 1) if assign_positions else 0
    for j in list(range(0, cutoff)) + list(range(rhs_start, len(toks))):
        tk = toks[j]
        if tk.kind == "ident" and tk.text in state_vars and tk.text not in written:
            reads.add(tk.text)
    return reads


def _statement_ignores_return(stmt: Stmt, call: CallInfo) -> bool:
    """调用返回的 bool 是否被检查（用于危险低级调用规则）。

    被视为“已检查”的形态（任一即可）：
      - require( ... call(...) ... )
      - 调用结果出现在 if/while 条件中
      - require(!ok) 形式的命名结果，且 ok 来自该调用（保守近似）
    其余 (bool ok, ) = target.call(...) 后未使用、或裸 target.call(...) 视为未检查。
    """
    toks = stmt.tokens
    # require( 包裹
    for j, tk in enumerate(toks):
        if tk.text == "require" and j + 1 < len(toks) and toks[j + 1].text == "(":
            open_idx = j + 1
            close = _find_matching(toks, open_idx, "(", ")")
            if close != -1 and open_idx < call.call_token_index < close:
                return False
    # 赋值给具名变量，之后由调用者跨语句判断；此处先返回 True 表示“本语句未直接检查”
    return True


# ---------------------------------------------------------------- 合约级分析


@dataclass
class FunctionAnalysis:
    fn: Function
    statements: list[Stmt]
    state_writes: list[set[str]]   # 每条语句写入的状态变量
    state_reads: list[set[str]]    # 每条语句读取的状态变量
    calls: list[list[CallInfo]]    # 每条语句的调用


def _analyze_function(contract: Contract, fn: Function) -> FunctionAnalysis:
    state_vars = _state_var_names(contract)
    local_vars = set(fn.local_vars)
    statements: list[Stmt] = []
    writes_l: list[set[str]] = []
    reads_l: list[set[str]] = []
    calls_l: list[list[CallInfo]] = []
    if fn.body is not None:
        statements = flatten_statements(fn.body)
        for idx, st in enumerate(statements):
            w = _written_state_vars(st, state_vars)
            r = _read_state_vars(st, state_vars, w)
            c = extract_calls(st, idx, local_vars)
            writes_l.append(w)
            reads_l.append(r)
            calls_l.append(c)
    return FunctionAnalysis(fn, statements, writes_l, reads_l, calls_l)


def _modifier_is_mutex(mod: ModifierDef, state_var_names: set[str]) -> bool:
    """判断 modifier 是否为互斥锁守卫。

    结构判据（同时满足）：
      - 主体中存在 ``_;`` 占位符；
      - 在 ``_;`` 之前存在引用某个合约状态变量的 ``require(...)`` 守卫
        （如 require(!locked) / require(locked == false)）。
    不使用命名启发式：是否成锁完全由结构与状态变量决定。
    """
    stmts = flatten_statements(mod.body)
    guarded_before_placeholder = False

    for st in stmts:
        texts = [t.text for t in st.tokens]
        if "require" in texts:
            # 提取 require(...) 内部 token
            ri = next(k for k, t in enumerate(st.tokens) if t.text == "require")
            if ri + 1 < len(st.tokens) and st.tokens[ri + 1].text == "(":
                close = _find_matching(st.tokens, ri + 1, "(", ")")
                inner = st.tokens[ri + 2 : close] if close != -1 else []
                inner_texts = {t.text for t in inner}
                refs_state = bool(inner_texts & state_var_names)
                # 守卫语义：取反(!) 或 与 false 比较
                negated = any(t.text == "!" for t in inner) or "false" in inner_texts
                if refs_state and negated:
                    guarded_before_placeholder = True
        elif "_" in texts:
            # 占位符出现：此前是否已有结构守卫
            return guarded_before_placeholder
    return False


@dataclass
class ContractAnalysis:
    contract: Contract
    functions: list[FunctionAnalysis]
    mutex_modifiers: set[str]


def analyze_contract(contract: Contract) -> ContractAnalysis:
    state_names = _state_var_names(contract)
    mutex = {
        m.name
        for m in contract.modifier_defs
        if _modifier_is_mutex(m, state_names)
    }
    fns = [
        _analyze_function(contract, fn)
        for fn in contract.functions
        if fn.body is not None
    ]
    return ContractAnalysis(contract, fns, mutex)


def _fn_has_mutex(fn: Function, mutex: set[str]) -> bool:
    return any(m.name in mutex for m in fn.modifiers)


def _snippet(project: ResolvedProject, file: str, line: int) -> str:
    content = project.sources.get(file, "")
    lines = content.splitlines()
    if 1 <= line <= len(lines):
        return lines[line - 1].strip()
    return ""


# ---------------------------------------------------------------- 规则实现


def _location(project: ResolvedProject, file: str, call: CallInfo, contract: Contract, fn: Function) -> Location:
    return Location(
        file=file,
        line=call.line,
        column=call.column,
        contract=contract.name,
        function=fn.name,
        snippet=_snippet(project, file, call.line),
    )


def _iter_analyses(project: ResolvedProject):
    for file in project.order:
        unit: SourceUnit = project.units[file]
        for contract in unit.contracts:
            if contract.kind in ("interface", "library"):
                continue
            yield file, contract, analyze_contract(contract)


def _guarded_sibling_writes(
    analysis: ContractAnalysis, fn: Function, vars_: set[str]
) -> list[tuple[Function, set[str]]]:
    """其它对 vars_ 中任一状态变量有写入、且未被互斥锁保护的函数。"""
    result = []
    for fa in analysis.functions:
        if fa.fn is fn:
            continue
        if fa.fn.kind != "function" or fa.fn.visibility not in ("public", "external"):
            continue
        if _fn_has_mutex(fa.fn, analysis.mutex_modifiers):
            continue
        written: set[str] = set().union(*fa.state_writes) if fa.state_writes else set()
        hit = written & vars_
        if hit:
            result.append((fa.fn, hit))
    return result


def _call_return_checked_later(fa: FunctionAnalysis, call: CallInfo) -> bool:
    """调用结果被赋给具名 bool 后，是否在后续语句的 require/条件中使用。"""
    stmt = call.statement
    toks = stmt.tokens
    # 找赋值左值中的名字（(bool ok, ) = ...）
    assign = _top_level_assignments(toks)
    if not assign:
        return False
    lhs = toks[: min(assign)]
    names = [t.text for t in lhs if t.kind == "ident" and t.text not in {"bool", "true", "false"}]
    if not names:
        return False
    # 扫描该语句之后的全部语句
    for later in fa.statements[call.stmt_index + 1 :]:
        texts = [t.text for t in later.tokens]
        if any(name in texts for name in names) and (
            "require" in texts or later.kind in ("if", "loop")
        ):
            return True
        # 也检查 if/while 条件 token
        if later.condition and any(
            t.text in names for t in later.condition
        ):
            return True
    return False


def evaluate_reentrancy(project: ResolvedProject) -> list[Finding]:
    """REENTRANCY-001：外部调用后才更新状态，且不存在互斥锁保护。

    - 若被读状态在另一个未加锁的外部函数中也可被写入 => 跨函数重入（CRITICAL）；
    - 否则若本函数调用后才写入 => 同函数重入（HIGH）；
    - 函数被互斥锁 modifier 保护时不报重入（与“受锁保护重入”对照）。
    """
    findings: list[Finding] = []
    for file, contract, analysis in _iter_analyses(project):
        for fa in analysis.functions:
            fn = fa.fn
            if fn.visibility not in ("public", "external"):
                continue
            if _fn_has_mutex(fn, analysis.mutex_modifiers):
                continue
            for idx, calls in enumerate(fa.calls):
                external = [c for c in calls if c.kind in ("low-level", "high-level")]
                # transfer/send 不转发全部 gas，默认不构成重入面
                external = [c for c in external if not (c.kind == "low-level" and c.method in SAFE_VALUE_METHODS)]
                if not external:
                    continue
                # 调用点之后（严格晚于该语句）的状态写入
                later_writes: set[str] = set()
                for w in fa.state_writes[idx + 1 :]:
                    later_writes |= w
                # 调用点之前读取、之后写入的状态变量（重入可观察的陈旧状态）
                prior_reads: set[str] = set()
                for r in fa.state_reads[: idx + 1]:
                    prior_reads |= r
                stale = later_writes & prior_reads
                any_later_writes = bool(later_writes)
                if not any_later_writes:
                    continue
                for call in external:
                    siblings = _guarded_sibling_writes(analysis, fn, later_writes | stale)
                    loc = _location(project, file, call, contract, fn)
                    if siblings:
                        sib_names = sorted(s.name for s, _ in siblings)
                        findings.append(
                            Finding(
                                key=reentrancy_key(file, loc),
                                rule_ids=["REENTRANCY-001"],
                                category="reentrancy",
                                title="跨函数重入风险 (cross-function reentrancy)",
                                severity=Severity.CRITICAL,
                                description=(
                                    f"函数 {fn.name} 在状态更新前执行外部调用，且共享状态可经由未加锁的"
                                    f"兄弟函数 {', '.join(sib_names)} 被重入改写，攻击者可在状态落盘前"
                                    f"利用这些函数获取非法利益。"
                                ),
                                locations=[loc],
                                evidence=[
                                    f"external_call: {call.target_expr}.{call.method} @ line {call.line}",
                                    f"state_updated_after_call: {sorted(later_writes)}",
                                    f"unguarded_sibling_writers: {sib_names}",
                                ],
                            )
                        )
                    else:
                        findings.append(
                            Finding(
                                key=reentrancy_key(file, loc),
                                rule_ids=["REENTRANCY-001"],
                                category="reentrancy",
                                title="同函数重入风险 (same-function reentrancy)",
                                severity=Severity.HIGH,
                                description=(
                                    f"函数 {fn.name} 先执行外部调用、后更新状态 "
                                    f"{sorted(later_writes)}，攻击者可在调用返回前重入该函数"
                                    f"读取到陈旧状态。建议遵循 checks-effects-interactions 顺序。"
                                ),
                                locations=[loc],
                                evidence=[
                                    f"external_call: {call.target_expr}.{call.method} @ line {call.line}",
                                    f"state_updated_after_call: {sorted(later_writes)}",
                                ],
                            )
                        )
    return findings


def reentrancy_key(file: str, loc: Location) -> str:
    return f"reentrancy@{file}:{loc.contract}.{loc.function}:{loc.line}:{loc.column}"


def evaluate_dangerous_calls(project: ResolvedProject) -> list[Finding]:
    """DANGEROUS-CALL-001：未检查返回值的危险低级调用 / delegatecall。

    - ``delegatecall`` 让目标在本合约存储上下文中执行，始终高危（HIGH）；
    - 未检查返回值的 ``call`` 为 MEDIUM；
    - transfer/send 语义受限，不重复报告。
    与重入规则命中同一调用点时，由引擎层按定位合并去重。
    """
    findings: list[Finding] = []
    for file, contract, analysis in _iter_analyses(project):
        for fa in analysis.functions:
            fn = fa.fn
            for idx, calls in enumerate(fa.calls):
                for call in calls:
                    if call.kind != "low-level":
                        continue
                    if call.method in SAFE_VALUE_METHODS:
                        continue
                    loc = _location(project, file, call, contract, fn)
                    if call.method == "delegatecall":
                        findings.append(
                            Finding(
                                key=dangerous_key(file, loc),
                                rule_ids=["DANGEROUS-CALL-001"],
                                category="dangerous-external-call",
                                title="危险的 delegatecall",
                                severity=Severity.HIGH,
                                description=(
                                    "delegatecall 使外部代码在本合约存储与地址上下文中运行，"
                                    "目标不可信时可完全接管合约状态。"
                                ),
                                locations=[loc],
                                evidence=[f"delegatecall target: {call.target_expr} @ line {call.line}"],
                            )
                        )
                        continue
                    if call.method not in ("call",):
                        continue
                    # 返回值是否被检查
                    checked = (not _statement_ignores_return(call.statement, call)) or _call_return_checked_later(fa, call)
                    if checked:
                        continue
                    findings.append(
                        Finding(
                            key=dangerous_key(file, loc),
                            rule_ids=["DANGEROUS-CALL-001"],
                            category="dangerous-external-call",
                            title="未检查返回值的低级 call",
                            severity=Severity.MEDIUM,
                            description=(
                                f"函数 {fn.name} 使用低级 call 发起外部调用但未检查其返回值，"
                                f"调用失败不会被感知，可能导致状态与实际转账不一致。"
                            ),
                            locations=[loc],
                            evidence=[f"unchecked low-level call: {call.target_expr}.call @ line {call.line}"],
                        )
                    )
    return findings


def dangerous_key(file: str, loc: Location) -> str:
    return f"dangerous-call@{file}:{loc.contract}.{loc.function}:{loc.line}:{loc.column}"


# ---------------------------------------------------------------- 规则注册表


def _make_rule(rule_id: str, fn):
    class _BoundRule:
        def __init__(self) -> None:
            self.id = rule_id
            self._fn = fn

        def evaluate(self, project: ResolvedProject) -> list[Finding]:
            return self._fn(project)

    return _BoundRule()


def default_rules() -> list[Rule]:
    """返回按固定顺序排列的全部内置规则（顺序即 rules_evaluated 的稳定顺序）。"""
    return [
        _make_rule("REENTRANCY-001", evaluate_reentrancy),
        _make_rule("DANGEROUS-CALL-001", evaluate_dangerous_calls),
    ]
