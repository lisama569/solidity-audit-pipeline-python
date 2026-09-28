"""基于规则的漏洞识别：重入（含跨函数）与危险外部调用。

实现为确定性的轻量静态分析：
1. 去除注释（保留行号）；
2. 解析 contract / function / modifier 结构（花括号配对）；
3. 收集状态变量与锁（重入保护）信息；
4. 在函数体内定位外部调用与状态写，按规则产出 RawHit。

同一处问题被多条规则命中时，由 engine 层按 (file, line, function) 合并。

另提供 compute_site_signatures：为每个外部调用站点生成**跨版本稳定签名**，
签名只依赖规范化后的函数体语义与调用点在函数内的序号，与行号、函数排列顺序、
整体位移、标识符命名和注释无关，供版本对比做问题匹配。
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


def _site_signature(
    file: str,
    contract: _Contract,
    fn: _Function,
    call_ordinal: int,
) -> str:
    body_canon, _ = _canonicalize(fn.body)
    skeleton_canon = _state_skeleton_canonical(contract)
    h = hashlib.sha256()
    for part in (file, skeleton_canon, body_canon, str(call_ordinal)):
        h.update(part.encode("utf-8"))
        h.update(b"\x00")
    return "S-" + h.hexdigest()[:14]


def compute_site_signatures(
    sources: dict[str, str], ordered_paths: list[str]
) -> dict[tuple[str, str, str, int], str]:
    """为每个外部调用站点计算跨版本稳定签名。

    返回 {(file, contract, function, line): 站点基础签名}。
    行号只作为字典键使用；签名内容本身不含行号，整体挪动/重排不受影响。
    """
    mapping: dict[tuple[str, str, str, int], str] = {}
    for path in ordered_paths:
        text = _strip_comments(sources[path])
        for contract in _parse_contracts(text):
            for fn in contract.functions:
                if fn.kind != "function":
                    continue
                for ordinal, cm in enumerate(
                    _EXT_CALL_RE.finditer(fn.body), start=1
                ):
                    line = _line_of(text, fn.body_offset + cm.start())
                    mapping[(path, contract.name, fn.name, line)] = (
                        _site_signature(path, contract, fn, ordinal)
                    )
    return mapping
