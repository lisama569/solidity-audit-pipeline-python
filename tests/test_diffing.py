"""版本对比核心测试：新增/已修复/仍存在/严重度变化、位移与重命名后的匹配、
稳定排序/统计/可复现性。
"""
from app import engine
from app.diffing import compare_reports, compute_site_signatures
from app.ingest import fingerprint, normalize_sources, resolve_imports
from app.models import AuditReport, DiffCategory, Finding, Severity, SourceFile

VULN = """
contract Vault {
    mapping(address => uint) balances;
    function withdraw() public {
        uint amount = balances[msg.sender];
        msg.sender.call{value: amount}("");
        balances[msg.sender] = 0;
    }
    function leak() public {
        msg.sender.send(1);
    }
}
"""

# 新版本：withdraw 修复（加 require，去掉后面的写 -> REENTRANCY 消失），
# leak 保留，新增 delegatecall
CUR_FIX_AND_NEW = """
contract Vault {
    mapping(address => uint) balances;
    function withdraw() public {
        uint amount = balances[msg.sender];
        require(msg.sender.call{value: amount}(""));
    }
    function leak() public {
        msg.sender.send(1);
    }
    function evil(address t) public {
        t.delegatecall("");
    }
}
"""


def _audit(src: str, name: str = "Vault.sol", fp: str = "fp"):
    sources = normalize_sources([SourceFile(name, src)])
    if fp == "fp":
        fp = fingerprint(sources)
    ordered = resolve_imports(sources)
    report = engine.audit(fp, sources, ordered)
    sigs = compute_site_signatures(sources, ordered)
    return report, sigs


def _by_function(diff, category):
    return [
        (e.current_finding or e.baseline_finding).function
        for e in diff.entries if e.category is category
    ]


def test_new_fixed_persisting_classification():
    base, bs = _audit(VULN, fp="base")
    cur, cs = _audit(CUR_FIX_AND_NEW, fp="cur")
    diff = compare_reports(cur, base, "base-task", cs, bs)
    assert diff.baseline_task_id == "base-task"
    assert diff.baseline_fingerprint == "base"
    assert diff.current_fingerprint == "cur"
    assert _by_function(diff, DiffCategory.NEW) == ["evil"]
    assert _by_function(diff, DiffCategory.FIXED) == ["withdraw"]
    assert _by_function(diff, DiffCategory.PERSISTING) == ["leak"]
    assert diff.counts == {
        "NEW": 1, "FIXED": 1, "PERSISTING": 1,
        "SEVERITY_CHANGED": 0, "total": 3,
    }
    print(f"[diff] 新增/已修复/仍存在 -> {diff.counts}")


def test_severity_change_via_constructed_findings():
    # 同站点身份、同规则集、严重程度不同 -> SEVERITY_CHANGED
    from app.rules import SiteInfo

    info = SiteInfo(
        group_key="G-site", ordinal_key="O-site",
        function_ordinal=0, call_ordinal=1,
        body_canon="B-site", stable_sig="S-site",
    )
    site = {("a.sol", "C", "f", 10): info}
    f = lambda sev: Finding(
        "F-x", ("RULE_X",), sev, "a.sol", 10, "C", "f", "msg"
    )
    base = AuditReport("b", (f(Severity.HIGH),), False, "bh")
    cur = AuditReport("c", (f(Severity.LOW),), False, "ch")
    diff = compare_reports(cur, base, "t", site, site)
    assert diff.counts["SEVERITY_CHANGED"] == 1
    e = diff.entries[0]
    assert e.baseline_severity is Severity.HIGH
    assert e.current_severity is Severity.LOW
    assert e.baseline_finding.severity is Severity.HIGH
    assert e.current_finding.severity is Severity.LOW
    print("[diff] 严重程度变化 HIGH->LOW -> SEVERITY_CHANGED")


def test_shift_and_rename_keeps_persisting():
    # 顶部插入无关合约/函数（整体下移）、纯标识符重命名、加注释、函数重排：
    # 原有实质未变的问题必须仍匹配为 PERSISTING，不能变新增/已修复。
    moved = """
// 顶部新增的无关注释
contract Helpers {
    function noop() public pure returns (uint) { return 42; }
}

contract Vault {
    mapping(address => uint) balances;
    function leak() public {
        msg.sender.send(1);
    }
    function withdraw() public {
        uint amount = balances[msg.sender];
        msg.sender.call{value: amount}("");
        balances[msg.sender] = 0;
    }
}
"""
    renamed = """
contract Wallet {
    mapping(address => uint) credit;
    function take() public {
        uint sum = credit[msg.sender];
        msg.sender.call{value: sum}("");
        credit[msg.sender] = 0;
    }
    function drip() public {
        msg.sender.send(1);
    }
}
"""
    base, bs = _audit(VULN, fp="base")
    moved_rep, ms = _audit(moved, fp="moved")
    renamed_rep, rs = _audit(renamed, fp="renamed")

    for tag, rep, sigs in (("整体位移", moved_rep, ms), ("纯重命名", renamed_rep, rs)):
        diff = compare_reports(rep, base, "t", sigs, bs)
        assert diff.counts["NEW"] == 0, (tag, diff.counts)
        assert diff.counts["FIXED"] == 0, (tag, diff.counts)
        assert diff.counts["PERSISTING"] == 2, (tag, diff.counts)
        print(f"[diff] {tag}后匹配 -> 全部 PERSISTING {diff.counts}")


def test_unchanged_inputs_identical_diff():
    # 两份完全相同的报告互比：全 PERSISTING，无新增/修复/变化
    rep, sigs = _audit(VULN, fp="same")
    diff = compare_reports(rep, rep, "t", sigs, sigs)
    assert diff.counts["PERSISTING"] == 2
    assert diff.counts["total"] == 2
    assert diff.current_report_hash == diff.baseline_report_hash


def test_ordering_and_counts_stable():
    # 分类顺序固定 NEW < FIXED < PERSISTING < SEVERITY_CHANGED；同类按签名稳定
    base, bs = _audit(VULN, fp="base")
    cur, cs = _audit(CUR_FIX_AND_NEW, fp="cur")
    d1 = compare_reports(cur, base, "t", cs, bs)
    d2 = compare_reports(cur, base, "t", cs, bs)
    assert d1.diff_hash == d2.diff_hash
    cats = [e.category for e in d1.entries]
    rank = {DiffCategory.NEW: 0, DiffCategory.FIXED: 1,
            DiffCategory.PERSISTING: 2, DiffCategory.SEVERITY_CHANGED: 3}
    assert [rank[c] for c in cats] == sorted(rank[c] for c in cats)
    # entries 总数与统计一致
    assert d1.counts["total"] == len(d1.entries)
    print(f"[diff] 稳定排序与统计 -> hash={d1.diff_hash[:16]}")


def test_direction_matters():
    # 反向对比（新版本当基线）：NEW/FIXED 对调，hash 不同
    base, bs = _audit(VULN, fp="base")
    cur, cs = _audit(CUR_FIX_AND_NEW, fp="cur")
    forward = compare_reports(cur, base, "t", cs, bs)
    backward = compare_reports(base, cur, "t", bs, cs)
    assert forward.counts["NEW"] == backward.counts["FIXED"]
    assert forward.counts["FIXED"] == backward.counts["NEW"]
    assert forward.diff_hash != backward.diff_hash


def _many_funcs(n_fixed=0, n_new=0, n_keep=0, shift_lines=0):
    """生成包含多个外部调用函数的合约文本；每类问题各若干条。"""
    pad = "\n".join(f"function pad{i}() public pure returns (uint) {{ return {i}; }}"
                    for i in range(shift_lines))
    parts = [f"contract Big {{ mapping(address => uint) v; {pad}"]
    for i in range(n_keep):  # 保留：未检查 call 后写状态（新旧都有）
        parts.append(
            f"function keep{i}() public {{ address a=msg.sender;"
            f"a.call(\"\"); v[a]={i}; }}"
        )
    for i in range(n_fixed):  # 仅基线有
        parts.append(
            f"function gone{i}() public {{ address a=msg.sender;"
            f"a.call(\"\"); v[a]={i+1000}; }}"
        )
    for i in range(n_new):  # 仅新版本有
        parts.append(
            f"function born{i}(address t) public {{ t.delegatecall(\"\"); }}"
        )
    parts.append("}")
    return "\n".join(parts)


def test_hundreds_of_findings_stable():
    base_src = _many_funcs(n_keep=120, n_fixed=80, n_new=0, shift_lines=0)
    # 新版本：保留项整体下移（顶部插入 100 行无关函数）+ 80 修复 + 100 新增
    cur_src = _many_funcs(n_keep=120, n_fixed=0, n_new=100, shift_lines=100)
    base, bs = _audit(base_src, "Big.sol", fp="base")
    cur, cs = _audit(cur_src, "Big.sol", fp="cur")
    assert len(base.findings) == 200
    assert len(cur.findings) == 220

    d1 = compare_reports(cur, base, "t", cs, bs)
    d2 = compare_reports(cur, base, "t", cs, bs)
    assert d1 == d2
    assert d1.diff_hash == d2.diff_hash
    assert d1.counts == {
        "NEW": 100, "FIXED": 80, "PERSISTING": 120,
        "SEVERITY_CHANGED": 0, "total": 300,
    }
    # 顺序稳定：分类块有序，同块内签名非递减
    rank = {DiffCategory.NEW: 0, DiffCategory.FIXED: 1,
            DiffCategory.PERSISTING: 2, DiffCategory.SEVERITY_CHANGED: 3}
    keys = [(rank[e.category], e.signature) for e in d1.entries]
    assert keys == sorted(keys)
    print(f"[diff] 300 条结论 -> 分类/顺序/统计稳定 hash={d1.diff_hash[:16]}")
