"""规则层对照测试：跨函数重入 vs 受锁保护重入、危险外部调用。"""
from app.ingest import normalize_sources, resolve_imports
from app.models import Severity, SourceFile
from app.rules import RULE_DANGEROUS_CALL, RULE_REENTRANCY, run_rules

REENTRANCY_INTRA = """
contract Vault {
    mapping(address => uint) balances;
    function withdraw() public {
        uint amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}
"""

REENTRANCY_CROSS_FN = """
contract Vault {
    mapping(address => uint) balances;
    function withdraw() public {
        uint amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        _settle(msg.sender);
    }
    function _settle(address who) internal {
        balances[who] = 0;
    }
}
"""

REENTRANCY_LOCKED = """
contract Vault {
    mapping(address => uint) balances;
    bool locked;
    modifier nonReentrant() {
        require(!locked);
        locked = true;
        _;
        locked = false;
    }
    function withdraw() public nonReentrant {
        uint amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}
"""

DANGEROUS_DELEGATECALL = """
contract Proxy {
    function forward(address target, bytes memory data) public {
        target.delegatecall(data);
    }
}
"""

UNCHECKED_CALL = """
contract Pay {
    function pay(address to, uint amount) public {
        to.call{value: amount}("");
    }
}
"""

SAFE_CONTRACT = """
contract Counter {
    uint public count;
    function inc() public {
        count += 1;
    }
}
"""


def _hits(src: str, name: str = "Vault.sol"):
    sources = normalize_sources([SourceFile(name, src)])
    return run_rules(sources, resolve_imports(sources))


def test_intra_function_reentrancy():
    hits = _hits(REENTRANCY_INTRA)
    re = [h for h in hits if h.rule_id == RULE_REENTRANCY]
    assert len(re) == 1
    assert re[0].severity == Severity.HIGH
    assert re[0].function == "withdraw" and re[0].line == 6
    print(f"[rule] 函数内重入 -> {re[0].rule_id} L{re[0].line} {re[0].message}")


def test_cross_function_reentrancy():
    hits = _hits(REENTRANCY_CROSS_FN)
    re = [h for h in hits if h.rule_id == RULE_REENTRANCY]
    assert len(re) == 1
    assert "跨函数" in re[0].message
    print(f"[rule] 跨函数重入 -> {re[0].rule_id} L{re[0].line} {re[0].message}")


def test_lock_protected_reentrancy_suppressed():
    hits = _hits(REENTRANCY_LOCKED)
    re = [h for h in hits if h.rule_id == RULE_REENTRANCY]
    assert re == []
    print("[rule] 受锁保护 -> 无 REENTRANCY 命中（对照通过）")


def test_delegatecall_dangerous():
    hits = _hits(DANGEROUS_DELEGATECALL, "Proxy.sol")
    dc = [h for h in hits if h.rule_id == RULE_DANGEROUS_CALL]
    assert len(dc) == 1 and dc[0].severity == Severity.HIGH
    print(f"[rule] delegatecall -> {dc[0].rule_id} L{dc[0].line} {dc[0].message}")


def test_unchecked_low_level_call():
    hits = _hits(UNCHECKED_CALL, "Pay.sol")
    dc = [h for h in hits if h.rule_id == RULE_DANGEROUS_CALL]
    assert len(dc) == 1 and dc[0].severity == Severity.MEDIUM
    print(f"[rule] 未检查返回值 call -> {dc[0].rule_id} L{dc[0].line} {dc[0].message}")


def test_safe_contract_no_hits():
    assert _hits(SAFE_CONTRACT, "Counter.sol") == []
    print("[rule] 安全合约 -> 无命中")


def test_hits_deterministic_across_runs():
    a = _hits(REENTRANCY_CROSS_FN)
    b = _hits(REENTRANCY_CROSS_FN)
    assert a == b
