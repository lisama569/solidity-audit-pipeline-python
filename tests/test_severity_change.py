"""严重程度变化（SEVERITY_CHANGED）专项测试。

用真实 Solidity 版本演进（经 ingest -> rules -> engine -> diffing 全链路）
覆盖：
- 严重程度升高（send 返回值未检查 LOW -> 低层 call 返回值未检查 MEDIUM）；
- 严重程度降低（call -> send，反向演进）；
- 代码位置整体挪动（顶部插入合约/函数）、纯重命名、函数重排之后，
  严重程度变化依然能正确匹配；
- 边界：原问题确实删掉、旁边新增另一个不同问题 -> NEW+FIXED，不得合并；
- 可复现性：重复对比的分类、条数、顺序与整体哈希完全一致。
"""
from app import engine
from app.diffing import compare_reports, compute_site_signatures
from app.ingest import fingerprint, normalize_sources, resolve_imports
from app.models import DiffCategory, Severity, SourceFile


def _audit(src: str, name: str = "Vault.sol", tag: str = "fp"):
    sources = normalize_sources([SourceFile(name, src)])
    ordered = resolve_imports(sources)
    fp = tag + ":" + fingerprint(sources)
    report = engine.audit(fp, sources, ordered)
    sigs = compute_site_signatures(sources, ordered)
    return report, sigs


def _changed_entries(diff):
    return [e for e in diff.entries
            if e.category is DiffCategory.SEVERITY_CHANGED]


# 低危：send 返回值未检查（DANGEROUS_EXTERNAL_CALL / LOW）
SEND_UNCHECKED = """
contract Vault {
    function withdraw(address payable to, uint amount) public {
        to.send(amount);
    }
}
"""

# 中危：同一站点改成低层 call，返回值同样未检查
CALL_UNCHECKED = """
contract Vault {
    function withdraw(address payable to, uint amount) public {
        to.call{value: amount}("");
    }
}
"""


def test_severity_increase_send_to_call():
    base, bs = _audit(SEND_UNCHECKED, tag="base")
    cur, cs = _audit(CALL_UNCHECKED, tag="cur")
    assert base.findings[0].severity is Severity.LOW
    assert cur.findings[0].severity is Severity.MEDIUM

    diff = compare_reports(cur, base, "base-task", cs, bs)
    assert diff.counts == {
        "NEW": 0, "FIXED": 0, "PERSISTING": 0,
        "SEVERITY_CHANGED": 1, "total": 1,
    }
    e = _changed_entries(diff)[0]
    assert e.baseline_severity is Severity.LOW
    assert e.current_severity is Severity.MEDIUM
    assert e.baseline_finding.function == "withdraw"
    assert e.current_finding.function == "withdraw"
    assert e.rule_ids == ("DANGEROUS_EXTERNAL_CALL",)
    print("[sev] 严重程度升高 LOW->MEDIUM -> SEVERITY_CHANGED",
          f"{e.baseline_severity.name}->{e.current_severity.name}")


def test_severity_decrease_call_to_send():
    cur, cs = _audit(SEND_UNCHECKED, tag="cur")
    base, bs = _audit(CALL_UNCHECKED, tag="base")
    diff = compare_reports(cur, base, "base-task", cs, bs)
    assert diff.counts["SEVERITY_CHANGED"] == 1
    assert diff.counts["NEW"] == 0 and diff.counts["FIXED"] == 0
    e = _changed_entries(diff)[0]
    assert e.baseline_severity is Severity.MEDIUM
    assert e.current_severity is Severity.LOW
    print("[sev] 严重程度降低 MEDIUM->LOW -> SEVERITY_CHANGED")


def test_severity_change_survives_shift_and_rename():
    # 顶部插入无关合约 + 纯重命名（合约/函数/变量/参数）+ 函数顺序调整，
    # 同一站点仍须匹配为严重程度变化；旁边一条未变的 send 仍为 PERSISTING。
    base_src = """
contract Vault {
    mapping(address => uint) balances;
    function keepUnchanged(address x) public { x.send(2); }
    function withdraw(address payable to, uint amount) public {
        to.send(amount);
    }
}
"""
    cur_src = """
// 顶部新增的无关注释
contract Helpers {
    function noop() public pure returns (uint) { return 42; }
}

contract WalletRenamed {
    mapping(address => uint) credit;
    function payRenamed(address payable beneficiary, uint sum) public {
        beneficiary.call{value: sum}("");
    }
    function keepMoved(address other) public { other.send(2); }
}
"""
    base, bs = _audit(base_src, tag="base")
    cur, cs = _audit(cur_src, tag="cur")
    diff = compare_reports(cur, base, "t", cs, bs)
    assert diff.counts == {
        "NEW": 0, "FIXED": 0, "PERSISTING": 1,
        "SEVERITY_CHANGED": 1, "total": 2,
    }
    changed = _changed_entries(diff)[0]
    assert changed.baseline_severity is Severity.LOW
    assert changed.current_severity is Severity.MEDIUM
    # 跨版本函数已改名，按两侧各自的名字核对
    assert changed.baseline_finding.function == "withdraw"
    assert changed.current_finding.function == "payRenamed"
    persisting = [e for e in diff.entries
                  if e.category is DiffCategory.PERSISTING][0]
    assert persisting.baseline_finding.function == "keepUnchanged"
    assert persisting.current_finding.function == "keepMoved"
    assert persisting.baseline_severity is Severity.LOW
    print("[sev] 整体挪动+纯重命名+函数重排后仍识别严重程度变化")


def test_severity_change_after_prepended_function():
    # 前面新增一个函数导致整体序号下移：严重度变化仍须认出，不得变修复/新增。
    base_src = """
contract Vault {
    function target(address payable t, uint v) public { t.send(v); }
}
"""
    cur_src = """
contract Vault {
    function prependHelper(address x) public pure { x; }
    function target(address payable t, uint v) public {
        t.call{value: v}("");
    }
}
"""
    base, bs = _audit(base_src, tag="base")
    cur, cs = _audit(cur_src, tag="cur")
    diff = compare_reports(cur, base, "t", cs, bs)
    assert diff.counts["SEVERITY_CHANGED"] == 1
    assert diff.counts["NEW"] == 0 and diff.counts["FIXED"] == 0
    print("[sev] 前置插入函数（整体下移）后仍识别严重程度变化")


def test_fixed_in_place_plus_unrelated_new_not_merged():
    # 原问题在原地被修复（加 require，站点不再产出结论），旁边另一个函数
    # 新增了并非同一个的问题（delegatecall）-> FIXED + NEW，
    # 绝不能硬合并成一条严重程度变化。
    base_src = """
contract Vault {
    function a(address payable to) public { to.send(1); }
}
"""
    cur_src = """
contract Vault {
    function a(address payable to) public { require(to.send(1)); }
    function b(address t) public { t.delegatecall(""); }
}
"""
    base, bs = _audit(base_src, tag="base")
    cur, cs = _audit(cur_src, tag="cur")
    diff = compare_reports(cur, base, "t", cs, bs)
    assert diff.counts == {
        "NEW": 1, "FIXED": 1, "PERSISTING": 0,
        "SEVERITY_CHANGED": 0, "total": 2,
    }
    fixed = [e for e in diff.entries if e.category is DiffCategory.FIXED][0]
    new = [e for e in diff.entries if e.category is DiffCategory.NEW][0]
    assert fixed.baseline_finding.function == "a"
    assert new.current_finding.function == "b"
    print("[sev] 原地修复+旁边新增不同问题 -> FIXED+NEW，不合并")


def test_severity_change_reproducible_order_and_hash():
    base, bs = _audit(SEND_UNCHECKED, tag="base")
    cur, cs = _audit(CALL_UNCHECKED, tag="cur")
    d1 = compare_reports(cur, base, "t", cs, bs)
    d2 = compare_reports(cur, base, "t", cs, bs)
    assert d1 == d2
    assert d1.diff_hash == d2.diff_hash
    cats = [e.category for e in d1.entries]
    rank = {DiffCategory.NEW: 0, DiffCategory.FIXED: 1,
            DiffCategory.PERSISTING: 2, DiffCategory.SEVERITY_CHANGED: 3}
    assert [rank[c] for c in cats] == sorted(rank[c] for c in cats)
    print(f"[sev] 重复对比分类/条数/顺序/哈希一致 hash={d1.diff_hash[:16]}")
