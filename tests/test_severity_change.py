"""真实 Solidity 版本演进下的「严重程度变化」专项测试。

覆盖：
- 严重程度升高（未检查 send LOW -> 未检查 call MEDIUM）；
- 严重程度降低（delegatecall+状态写 重入 HIGH -> send+状态写 重入 MEDIUM）；
- 代码位置整体挪动（顶部插入合约、函数重排、纯重命名）后严重程度变化仍能匹配；
- 反向边界：旧问题被删除、旁边新加一个并非同一个的问题 -> 不能硬合并；
- 分类/条数/顺序/哈希的确定性；
- 真实提交+审计链路上的端到端：并发重复提交与服务重启后完全一致。
"""
import threading

from app import engine
from app.diffing import compare_reports, compute_site_signatures
from app.ingest import fingerprint, normalize_sources, resolve_imports
from app.models import DiffCategory, Severity, SourceFile, TaskStatus
from app.store import TaskStore
from app.tasks import TaskManager

# ---------------------------------------------------------------------------
# 用例源码
# ---------------------------------------------------------------------------

# 基线：未检查返回值的 send -> DANGEROUS_EXTERNAL_CALL LOW
SEND_LOW = """
contract Vault {
    function leak() public {
        msg.sender.send(1);
    }
}
"""

# 新版本：同一处改成未检查返回值的底层 call -> MEDIUM（严重程度升高）
CALL_MEDIUM = """
contract Vault {
    function leak() public {
        msg.sender.call("");
    }
}
"""

# 基线：delegatecall 之后仍有状态写，且无锁 -> REENTRANCY HIGH
DELEGATE_HIGH = """
contract Vault {
    mapping(address => uint) scores;
    function settle(address t) public {
        t.delegatecall("");
        scores[t] = 1;
    }
}
"""

# 新版本：同一处改成 send 之后仍有状态写 -> REENTRANCY MEDIUM（严重程度降低）
SEND_MEDIUM = """
contract Vault {
    mapping(address => uint) scores;
    function settle(address t) public {
        t.send(1);
        scores[t] = 1;
    }
}
"""

# 严重程度升高 + 整体下移：顶部插入无关合约/函数、函数重排、纯重命名
CALL_MEDIUM_MOVED = """
// 顶部新增注释
contract Helpers {
    function noop() public pure returns (uint) { return 7; }
}

contract Wallet {
    function drip() public {
        msg.sender.call("");
    }
}
"""

# 反例：旧问题所在函数被整个删除（带其特有上下文），旁边新加的是结构上
# 不同的另一个问题——站点实质不同，不能硬合并成严重程度变化。
DELETE_BASE = """
contract Vault {
    mapping(address => uint) log;
    function leak(address who) public {
        log[who] = 1;
        who.send(1);
    }
}
"""
DELETE_AND_ADD = """
contract Vault {
    mapping(address => uint) log;
    function drip() public {
        msg.sender.call("");
    }
    function boom(address t) public {
        t.delegatecall("");
    }
}
"""

# 旧问题保留 + 旁边再新增一个问题（多重集不能错配成严重程度变化）
KEEP_AND_ADD = """
contract Vault {
    function leak() public {
        msg.sender.send(1);
    }
    function evil(address t) public {
        t.delegatecall("");
    }
}
"""


def _audit(src: str, name: str = "Vault.sol", fp: str | None = None):
    sources = normalize_sources([SourceFile(name, src)])
    fp = fp or fingerprint(sources)
    ordered = resolve_imports(sources)
    report = engine.audit(fp, sources, ordered)
    sigs = compute_site_signatures(sources, ordered)
    return report, sigs


def _only(diff, category: DiffCategory):
    return [e for e in diff.entries if e.category is category]


# ---------------------------------------------------------------------------
# 严重程度升高
# ---------------------------------------------------------------------------

def test_severity_upgrade_real_pipeline():
    base, bs = _audit(SEND_LOW, fp="base")
    cur, cs = _audit(CALL_MEDIUM, fp="cur")
    assert base.findings[0].severity is Severity.LOW
    assert cur.findings[0].severity is Severity.MEDIUM

    diff = compare_reports(cur, base, "base-task", cs, bs)
    assert diff.counts == {
        "NEW": 0, "FIXED": 0, "PERSISTING": 0,
        "SEVERITY_CHANGED": 1, "total": 1,
    }
    e = _only(diff, DiffCategory.SEVERITY_CHANGED)[0]
    assert e.baseline_severity is Severity.LOW
    assert e.current_severity is Severity.MEDIUM
    assert e.baseline_finding is not None and e.current_finding is not None
    assert e.baseline_finding.function == "leak"
    assert e.current_finding.function == "leak"
    assert e.rule_ids == ("DANGEROUS_EXTERNAL_CALL",)
    print("[sev] 未检查 send(LOW) -> 未检查 call(MEDIUM) -> SEVERITY_CHANGED")


# ---------------------------------------------------------------------------
# 严重程度降低
# ---------------------------------------------------------------------------

def test_severity_downgrade_real_pipeline():
    base, bs = _audit(DELEGATE_HIGH, fp="base")
    cur, cs = _audit(SEND_MEDIUM, fp="cur")
    base_re = [f for f in base.findings if "REENTRANCY" in f.rule_ids]
    cur_re = [f for f in cur.findings if "REENTRANCY" in f.rule_ids]
    assert len(base_re) == 1 and base_re[0].severity is Severity.HIGH
    assert len(cur_re) == 1 and cur_re[0].severity is Severity.MEDIUM

    diff = compare_reports(cur, base, "t", cs, bs)
    changed = _only(diff, DiffCategory.SEVERITY_CHANGED)
    # delegatecall 的 DANGEROUS_EXTERNAL_CALL(HIGH) 在新版本消失 -> FIXED；
    # 同处重入 HIGH -> MEDIUM -> SEVERITY_CHANGED
    re_changed = [e for e in changed if "REENTRANCY" in e.rule_ids]
    assert len(re_changed) == 1
    e = re_changed[0]
    assert e.baseline_severity is Severity.HIGH
    assert e.current_severity is Severity.MEDIUM
    print("[sev] delegatecall 重入(HIGH) -> send 重入(MEDIUM) -> SEVERITY_CHANGED")


# ---------------------------------------------------------------------------
# 整体挪动 + 重命名后的严重程度变化
# ---------------------------------------------------------------------------

def test_severity_change_survives_shift_and_rename():
    base, bs = _audit(SEND_LOW, fp="base")
    cur, cs = _audit(CALL_MEDIUM_MOVED, fp="cur")
    diff = compare_reports(cur, base, "t", cs, bs)
    assert diff.counts["SEVERITY_CHANGED"] == 1
    assert diff.counts["NEW"] == 0
    assert diff.counts["FIXED"] == 0
    assert diff.counts["PERSISTING"] == 0
    e = _only(diff, DiffCategory.SEVERITY_CHANGED)[0]
    # 新版本侧函数已改名/整体下移，但基线侧信息仍然完整给出
    assert e.baseline_finding.function == "leak"
    assert e.current_finding.function == "drip"
    assert (e.baseline_severity, e.current_severity) == (
        Severity.LOW, Severity.MEDIUM
    )
    print("[sev] 整体下移+合约/函数改名后 send->call 仍匹配为严重程度变化")


# ---------------------------------------------------------------------------
# 反例：删掉旧问题、旁边新加另一个问题，不能硬合并
# ---------------------------------------------------------------------------

def test_deleted_plus_new_unrelated_not_merged():
    base, bs = _audit(DELETE_BASE, fp="base")
    cur, cs = _audit(DELETE_AND_ADD, fp="cur")
    diff = compare_reports(cur, base, "t", cs, bs)
    assert diff.counts["SEVERITY_CHANGED"] == 0, diff.counts
    assert diff.counts["FIXED"] == 1
    assert diff.counts["NEW"] == 2  # 新函数里的未检查 call + delegatecall
    fixed = _only(diff, DiffCategory.FIXED)[0]
    assert fixed.baseline_finding.function == "leak"
    new_funcs = sorted(
        e.current_finding.function
        for e in _only(diff, DiffCategory.NEW)
    )
    assert new_funcs == ["boom", "drip"]
    print("[sev] 旧问题删除+旁边新加异质问题 -> FIXED/NEW，未误并为严重程度变化")


def test_kept_and_added_multiset_not_miscounted():
    base, bs = _audit(SEND_LOW, fp="base")
    cur, cs = _audit(KEEP_AND_ADD, fp="cur")
    diff = compare_reports(cur, base, "t", cs, bs)
    assert diff.counts == {
        "NEW": 1, "FIXED": 0, "PERSISTING": 1,
        "SEVERITY_CHANGED": 0, "total": 2,
    }
    assert _only(diff, DiffCategory.NEW)[0].current_finding.function == "evil"
    print("[sev] 同问题保留+旁边新增 -> PERSISTING+NEW，未错配")


# ---------------------------------------------------------------------------
# 确定性：重复对比、顺序、哈希
# ---------------------------------------------------------------------------

def test_severity_change_deterministic():
    base, bs = _audit(SEND_LOW, fp="base")
    cur, cs = _audit(CALL_MEDIUM, fp="cur")
    d1 = compare_reports(cur, base, "t", cs, bs)
    d2 = compare_reports(cur, base, "t", cs, bs)
    assert d1 == d2
    assert d1.diff_hash == d2.diff_hash

    # 反向对比是另一条 FIXED/NEW 形态之外的合法方向，这里严重程度变化对称：
    back = compare_reports(base, cur, "t2", bs, cs)
    back_e = _only(back, DiffCategory.SEVERITY_CHANGED)[0]
    assert (back_e.baseline_severity, back_e.current_severity) == (
        Severity.MEDIUM, Severity.LOW
    )
    assert back.diff_hash != d1.diff_hash
    print(f"[sev] 严重程度变化重复/反向对比确定 hash={d1.diff_hash[:16]}")


# ---------------------------------------------------------------------------
# 真实提交+审计链路：端到端、并发重复、重启复用
# ---------------------------------------------------------------------------

def _files(src: str, name: str = "Vault.sol"):
    return [(name, src.encode())]


def test_severity_change_end_to_end_concurrent_and_restart(tmp_path):
    db = str(tmp_path / "a.db")

    def new_manager(auto_recover=True):
        return TaskManager(TaskStore(db), timeout_seconds=10.0,
                           auto_recover=auto_recover)

    m = new_manager()
    b = m.wait_for(m.submit(_files(SEND_LOW)).task_id, deadline=10.0)
    assert b.status is TaskStatus.SUCCEEDED

    # 16 路并发提交同一对（新版本, 基线）
    results, barrier = [], threading.Barrier(16)

    def submit():
        barrier.wait()
        results.append(m.submit_diff(_files(CALL_MEDIUM), b.task_id))

    threads = [threading.Thread(target=submit) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    ids = {r.task_id for r in results}
    assert len(ids) == 1, f"并发产生 {len(ids)} 个对比任务"
    done = m.wait_for(ids.pop(), deadline=10.0)
    assert done.status is TaskStatus.SUCCEEDED
    diff = done.diff
    assert diff.counts["SEVERITY_CHANGED"] == 1
    assert diff.counts["NEW"] == 0 and diff.counts["FIXED"] == 0
    e = diff.entries[0]
    assert e.baseline_severity is Severity.LOW
    assert e.current_severity is Severity.MEDIUM
    saved_hash = diff.diff_hash

    # 再提交一次：命中同一任务、同一份结论
    again = m.submit_diff(_files(CALL_MEDIUM), b.task_id)
    assert again.task_id == done.task_id
    assert again.diff.diff_hash == saved_hash
    m.shutdown()

    # 服务重启后再查：任务、分类、条数、顺序、哈希全部一致
    m2 = new_manager(auto_recover=True)
    try:
        after = m2.submit_diff(_files(CALL_MEDIUM), b.task_id)
        assert after.task_id == done.task_id
        assert after.status is TaskStatus.SUCCEEDED
        assert after.diff == diff
        assert after.diff.diff_hash == saved_hash
        print(f"[sev-task] 16 路并发+重启复用 -> 单任务 {done.task_id[:8]} "
              f"LOW->MEDIUM hash={saved_hash[:16]}")
    finally:
        m2.shutdown()


# 同签名（规范化后同形）多重集失衡：基线 1 处 -> 新版本 2 处。
# 无法确定哪一处是原问题、哪一处是旁边新加的，必须保守记 FIXED/NEW，
# 而不是硬配出一条 SEVERITY_CHANGED。
DUP_BASE = """
contract Vault {
    function leak() public {
        msg.sender.send(1);
    }
}
"""
DUP_CUR = """
contract Vault {
    function leak() public {
        msg.sender.call("");
    }
    function leak2() public {
        msg.sender.call("");
    }
}
"""


def test_same_shape_multiset_imbalance_not_forced():
    base, bs = _audit(DUP_BASE, fp="base")
    cur, cs = _audit(DUP_CUR, fp="cur")
    diff = compare_reports(cur, base, "t", cs, bs)
    assert diff.counts["SEVERITY_CHANGED"] == 0, diff.counts
    assert diff.counts["FIXED"] == 1
    assert diff.counts["NEW"] == 2
    print("[sev] 同形多重集 1->2 失衡 -> 保守 FIXED/NEW，不硬并严重程度变化")
