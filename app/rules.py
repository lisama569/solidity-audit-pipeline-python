"""基于规则的漏洞识别：重入（含跨函数）与危险外部调用。

实现为确定性的轻量静态分析：
1. 去除注释（保留行号）；
2. 解析 contract / function / modifier 结构（花括号配对）；
3. 收集状态变量与锁（重入保护）信息；
4. 在函数体内定位外部调用与状态写，按规则产出 RawHit。

同一处问题被多条规则命中时，由 engine 层按 (file, line, function) 合并。

另提供 compute_site_signatures：为每个外部调用站点生成**跨版本身份信息**
（合约分组键、结构槽位键、外部调用形态规范化后的函数体、稳定展示签名），
与行号、函数排列顺序、整体位移、标识符命名和注释无关，供版本对比分两阶段
（原位配对 + 最小位移兜底）做问题匹配。

站点身份刻意不包含外部调用操作符（send/call/delegatecall/...）：操作符是
严重程度的判定因素，同一站点 send->call（低危升中危）或 call->send（中危
降低危）属于严重程度变化，若让操作符参与站点身份，这类演进会被误拆成
「新增 + 已修复」。
"""
from __future__ import annotations

import hashlib
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


@dataclass
class _Function:
    name: str
    kind: str  # function | modifier
    header: str
    body: str
    body_offset: int  # 相对文件开头的偏移


@dataclass(frozen=True)
class SiteInfo:
    """单个外部调用站点的跨版本身份信息（供版本对比分两阶段匹配）。

    - group_key：所属合约分组（文件 + 合约骨架），不含合约序号，
      因此在文件内前置插入/重排合约不受影响；同文件内多个同骨架合约
      （罕见）由 diffing 层按序号对齐消歧；
    - ordinal_key：严格结构键（合约分组 + 函数序号 + 调用序号），
      不含函数体语义，对整体挪动不敏感（函数体改动不改变序号）；
    - body_canon：外部调用形态已规范化的函数体文本，对纯重命名、注释、
      空白、调用操作符差异（send/transfer 与 call{value:…} 同属转账
      形态）不敏感；非转账低层调用的 calldata 与转账金额表达式仍按
      普通表达式参与规范化，用于区分不同站点；
    - has_finding 不在这里：站点信息对所有外部调用站点（含已修复、不再
      产出结论的站点）都生成，是否仍有结论由 diffing 层对照判断；
    - stable_sig：站点稳定签名（结构 + 语义组合哈希，供展示与未配对条目）。
    """

    group_key: str
    ordinal_key: str
    function_ordinal: int   # 合约内函数序号（仅用于最近位移配对，不含进签名）
    call_ordinal: int       # 函数内外调用点序号
    body_canon: str
    stable_sig: str


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
        writes = _state_writes(fn, contract.state_vars)
        protected = _is_protected(contract, fn)

        for cm in calls:
            op = cm.group(1)
            call_line = _line_of(text, fn.body_offset + cm.start())

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
                    )
                )
            elif op == "call":
                stmt_start = max(fn.body.rfind(";", 0, cm.start()),
                                 fn.body.rfind("{", 0, cm.start()),
                                 fn.body.rfind("}", 0, cm.start())) + 1
                stmt_end = fn.body.find(";", cm.end())
                stmt = fn.body[stmt_start : stmt_end if stmt_end != -1 else len(fn.body)]
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
                        )
                    )
            elif op == "send":
                stmt_start = max(fn.body.rfind(";", 0, cm.start()),
                                 fn.body.rfind("{", 0, cm.start()),
                                 fn.body.rfind("}", 0, cm.start())) + 1
                stmt_end = fn.body.find(";", cm.end())
                stmt = fn.body[stmt_start : stmt_end if stmt_end != -1 else len(fn.body)]
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
                        )
                    )

            # --- 规则：重入（call 之后仍存在状态写） ---
            if protected:
                continue
            later_write = any(w > cm.start() for w in writes)
            cross_fn = False
            if not later_write:
                tail = fn.body[cm.end() :]
                for callee in re.findall(r"\b([A-Za-z_]\w*)\s*\(", tail):
                    if callee in fn_by_name and callee != fn.name and writers.get(callee):
                        cross_fn = True
                        break
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


# ---------------------------------------------------------------------------
# 跨版本稳定站点签名
# ---------------------------------------------------------------------------

# Solidity 关键字 / 语言内建标识符 / 常见全局成员；其余标识符视为用户自定义名
_BUILTIN_IDS = frozenset(
    """
    pragma solidity contract library interface function modifier constructor
    fallback receive return returns public private internal external pure view
    payable constant immutable virtual override memory storage calldata new delete
    if else for while do break continue true false this super mapping struct enum
    event emit import using try catch throw type tuple unchecked assembly revert
    require assert anonymous indexed abstract address bool string byte bytes var
    uint int uint8 uint16 uint32 uint64 uint128 uint256 int8 int16 int32 int64
    int128 int256 bytes1 bytes4 bytes8 bytes16 bytes32 fixed ufixed wei gwei szabo
    finney ether seconds minutes hours days weeks years
    msg sender value data sig gas now block timestamp number coinbase difficulty
    gaslimit chainid basefee blobhash blobbasefee prevrandao tx origin gasprice
    gasleft blockhash selfdestruct suicide addmod mulmod keccak256 sha256
    ripemd160 ecrecover abi encode decode encodePacked encodeWithSignature
    encodeWithSelector length push pop balance code codehash codesize call send
    transfer delegatecall staticcall callcode selectorsupportsinterface
    """.split()
)
_BUILTIN_TYPE_RE = re.compile(r"^(u?int\d*|bytes\d*|u?fixed\d*x\d+|addresspayable)$")

# 外部调用操作符：是严重程度的判定因素，但不属于站点身份。
# 站点签名规范化时，把「转账语义」的调用形态统一成同一形状：
#   .send(x) / .transfer(x)                -> .valuetransfer(x)
#   .call{value: x, ...}(...)              -> .valuetransfer(x)
# 这样同一站点 send(amount) -> call{value: amount}("")（低危升中危）的
# 签名保持不变，由 diffing 层识别为严重程度变化；而不带 value 的
# call("")/delegatecall("") 是另一种形状，不会被错误等同。转账金额
# 表达式（send 的参数或 call 的 value 选项）按常规表达式一起槽位化/字面
# 归一，因此 send(2) 与 send(amount) 仍是不同站点，加上结构槽位约束，
# 多个同形站点之间不会错配；非转账低层调用保留其 calldata 参数。
_EXT_CALL_HEAD_RE = re.compile(
    r"\.\s*(call|delegatecall|callcode|send|transfer)\b"
)
_VALUE_TRANSFER_TOKEN = "valuetransfer"


def _skip_group(text: str, open_idx: int, open_ch: str, close_ch: str) -> int:
    """返回与 text[open_idx] 的括号配对的右括号下标（处理嵌套）。"""
    depth = 0
    i = open_idx
    while i < len(text):
        c = text[i]
        if c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return len(text) - 1


def _neutralize_ext_calls(body: str) -> str:
    """把函数体中的外部调用形态规范化（转账语义统一，其余仅去操作符差异）。

    - send/transfer：操作符替换为统一转账标记，参数表保留；
    - call/delegatecall/callcode 带 value 选项：连同选项与后续参数表一起
      归一为「转账标记(value 表达式)」；
    - 不带 value 的 call/delegatecall/callcode：操作符统一为通用低层调用
      标记，参数表保留（不与转账形态混淆）。
    """
    out: list[str] = []
    pos = 0
    for m in _EXT_CALL_HEAD_RE.finditer(body, pos):
        op = m.group(1)
        dot_idx = body.index(".", m.start())
        j = m.end()
        while j < len(body) and body[j].isspace():
            j += 1

        if op in ("send", "transfer"):
            out.append(body[pos:dot_idx])
            out.append("." + _VALUE_TRANSFER_TOKEN)
            pos = m.end(1)  # 保留参数表
            continue

        # call / delegatecall / callcode：检查 value 选项
        opts_text = None
        if j < len(body) and body[j] == "{":
            close = _skip_group(body, j, "{", "}")
            opts_text = body[j + 1:close]
            j = close + 1
            while j < len(body) and body[j].isspace():
                j += 1

        value_expr = None
        if opts_text is not None:
            vm = re.search(r"\bvalue\s*:\s*([^{}]+?)\s*(?:,|$)", opts_text)
            if vm:
                value_expr = vm.group(1).strip()

        # 旧式 .call.value(x)(...)（规则引擎本身不识别旧式调用，这里仅在
        # 站点签名侧做防御性归一）
        if value_expr is None:
            vm = re.match(r"\.\s*value\s*\(([^()]*)\)", body[j:])
            if vm:
                value_expr = vm.group(1).strip()
                j += vm.end()
                while j < len(body) and body[j].isspace():
                    j += 1

        if value_expr is not None and j < len(body) and body[j] == "(":
            close = _skip_group(body, j, "(", ")")
            out.append(body[pos:dot_idx])
            out.append("." + _VALUE_TRANSFER_TOKEN + "(" + value_expr + ")")
            pos = close + 1
        else:
            token = "lowlevelcall" if op == "call" else "lowleveldelegate"
            out.append(body[pos:m.start(1)])
            out.append(token)
            pos = m.end(1)

    out.append(body[pos:])
    return "".join(out)


def _canonicalize_for_site(code: str) -> tuple[str, dict[str, str]]:
    """站点签名专用规范化：先中和外部调用形态，再做标识符槽位化。

    与 _canonicalize 的区别是转账/低层调用操作符形态无关；纯重命名、
    注释/空白差异同样不影响结果。
    """
    neutralized = _neutralize_ext_calls(code)
    return _canonicalize(neutralized)

_TOKEN_RE = re.compile(
    r"""
      (?P<hex>0x[0-9a-fA-F]+)
    | (?P<number>\d+(?:\.\d+)?(?:e\d+)?)
    | (?P<string>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')
    | (?P<ident>[A-Za-z_$][A-Za-z0-9_$]*)
    | (?P<space>\s+)
    | (?P<other>.)
    """,
    re.VERBOSE | re.DOTALL,
)


def _canonicalize(code: str, slots: dict[str, str] | None = None) -> tuple[str, dict[str, str]]:
    """把代码规范化：用户自定义标识符按出现顺序槽位化（$0,$1,...），
    关键字/内建名/成员访问/类型名保持原样；字面量归一；空白折叠。

    纯重命名、注释差异（调用前已去注释）与空白差异不会改变规范化结果。
    """
    if slots is None:
        slots = {}
    out: list[str] = []
    last_sig = ""
    for m in _TOKEN_RE.finditer(code):
        kind = m.lastgroup
        tok = m.group()
        if kind == "space":
            if out and out[-1] != " ":
                out.append(" ")
        elif kind in ("hex", "number"):
            out.append("N")
        elif kind == "string":
            out.append("S")
        elif kind == "ident":
            word = tok
            if last_sig == ".":
                # 成员名（如 .call/.transfer/状态变量成员）属于语义，保持原样
                out.append(word)
            elif word in _BUILTIN_IDS or _BUILTIN_TYPE_RE.match(word.lower()):
                out.append(word)
            else:
                if word not in slots:
                    slots[word] = f"${len(slots)}"
                out.append(slots[word])
        else:
            out.append(tok)
        if kind != "space":
            last_sig = tok
    text = "".join(out).strip()
    text = re.sub(r"\s+", " ", text)
    return text, slots


def _state_skeleton_canonical(contract: _Contract) -> str:
    """合约骨架签名：状态变量声明序列（去函数体后按声明顺序，标识符槽位化）。

    用于区分同一文件内的不同合约；合约改名不影响结果。
    """
    funcs, skeleton = _parse_functions(
        contract.body, contract.body_offset
    )
    slots: dict[str, str] = {}
    parts: list[str] = []
    for m in _STATE_VAR_RE.finditer(skeleton):
        canon, slots = _canonicalize(m.group(0).strip(), slots)
        parts.append(canon)
    return "|".join(parts)


def _site_info(
    file: str,
    contract: _Contract,
    group_instance: int,
    fn: _Function,
    function_ordinal: int,
    call_ordinal: int,
) -> SiteInfo:
    body_canon, _ = _canonicalize_for_site(fn.body)
    skeleton_canon = _state_skeleton_canonical(contract)

    gh = hashlib.sha256()
    # group_instance 仅用于区分同一文件内多个同骨架合约；前置插入的是
    # 不同骨架合约时，同骨架合约的出现次序保持不变（位移不受影响）。
    for part in (file, skeleton_canon, str(group_instance)):
        gh.update(part.encode("utf-8"))
        gh.update(b"\x00")
    group_key = "G-" + gh.hexdigest()[:14]

    oh = hashlib.sha256()
    for part in (group_key, str(function_ordinal), str(call_ordinal)):
        oh.update(part.encode("utf-8"))
        oh.update(b"\x00")
    ordinal_key = "O-" + oh.hexdigest()[:14]

    h = hashlib.sha256()
    for part in (group_key, body_canon, str(call_ordinal)):
        h.update(part.encode("utf-8"))
        h.update(b"\x00")
    stable_sig = "S-" + h.hexdigest()[:14]

    return SiteInfo(
        group_key=group_key,
        ordinal_key=ordinal_key,
        function_ordinal=function_ordinal,
        call_ordinal=call_ordinal,
        body_canon=body_canon,
        stable_sig=stable_sig,
    )


def compute_site_signatures(
    sources: dict[str, str], ordered_paths: list[str]
) -> dict[tuple[str, str, str, int], SiteInfo]:
    """为每个外部调用站点计算跨版本身份信息。

    返回 {(file, contract, function, line): SiteInfo}。
    行号只作为字典键使用；内容本身不含行号，整体挪动/重排不受影响。
    """
    mapping: dict[tuple[str, str, str, int], SiteInfo] = {}
    for path in ordered_paths:
        text = _strip_comments(sources[path])
        seen_skeletons: dict[str, int] = {}
        for contract in _parse_contracts(text):
            skeleton_canon = _state_skeleton_canonical(contract)
            group_instance = seen_skeletons.get(skeleton_canon, 0)
            seen_skeletons[skeleton_canon] = group_instance + 1
            # 函数序号在合约内**全部**函数（含无外部调用的函数）上计数：
            # 这样序号相同才真正意味着"同一结构位置"，纯插入无调用函数
            # 导致的位移也能被阶段 2 的最小位移匹配正确追踪。
            for function_ordinal, fn in enumerate(contract.functions):
                if fn.kind != "function":
                    continue
                for call_ordinal, cm in enumerate(
                    _EXT_CALL_RE.finditer(fn.body), start=1
                ):
                    line = _line_of(text, fn.body_offset + cm.start())
                    mapping[(path, contract.name, fn.name, line)] = _site_info(
                        path, contract, group_instance,
                        fn, function_ordinal, call_ordinal,
                    )
    return mapping
