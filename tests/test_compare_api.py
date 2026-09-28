"""对比能力的端到端 HTTP 测试：提交流程、四类结论、基线拒绝、404、并发幂等。"""
import importlib
import threading

import pytest
from fastapi.testclient import TestClient

BASE = """
contract Vault {
    mapping(address => uint) balances;
    function keep() public {
        msg.sender.call{value: 1}("");
        balances[msg.sender] = 0;
    }
    function fixedFn(address t) public {
        uint mode = 1;
        t.delegatecall("");
    }
    function sevchg(address payable to) public {
        to.send(1);
    }
}
"""

NEW = """
contract Helper { uint helper; }
contract Vault {
    mapping(address => uint) ledger;
    function newFn(address to, uint amount) public {
        bool flag = true;
        to.call{value: amount}("");
    }
    function sevchg(address payable to) public {
        to.call{value: 1}("");
    }
    function keep() public {
        msg.sender.call{value: 1}("");
        ledger[msg.sender] = 0;
    }
}
"""


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDIT_DB_PATH", str(tmp_path / "api.db"))
    import main
    importlib.reload(main)
    with TestClient(main.app) as c:
        yield c
    main.manager.shutdown()
    main.comparator.shutdown()


def _audit(client, src, name="Vault.sol"):
    r = client.post(
        "/audits",
        files=[("files", (name, src, "text/plain"))],
    )
    assert r.status_code == 202
    tid = r.json()["task_id"]
    return _wait_audit(client, tid)


def _wait_audit(client, tid):
    import time
    end = time.time() + 10
    while time.time() < end:
        body = client.get(f"/audits/{tid}").json()
        if body["status"] in ("SUCCEEDED", "FAILED", "CANCELLED", "TIMEOUT"):
            return body
        time.sleep(0.02)
    raise AssertionError("审计未进入终态")


def _wait_compare(client, cid):
    import time
    end = time.time() + 10
    while time.time() < end:
        body = client.get(f"/comparisons/{cid}").json()
        if body["status"] in ("SUCCEEDED", "FAILED", "CANCELLED", "TIMEOUT"):
            return body
        time.sleep(0.02)
    raise AssertionError("对比未进入终态")


def _compare(client, src, baseline_id, name="Vault.sol"):
    return client.post(
        "/comparisons",
        data={"baseline_task_id": baseline_id},
        files=[("files", (name, src, "text/plain"))],
    )


def test_compare_endpoint_returns_classified_result(client):
    base = _audit(client, BASE)
    r = _compare(client, NEW, base["task_id"])
    assert r.status_code == 202, r.text
    cid = r.json()["compare_id"]
    body = _wait_compare(client, cid)
    assert body["status"] == "SUCCEEDED"
    result = body["result"]
    assert result["baseline_task_id"] == base["task_id"]
    assert result["counts"] == {"NEW": 1, "FIXED": 1, "PERSISTENT": 2,
                                "SEVERITY_CHANGED": 1}
    cats = {d["category"] for d in result["deltas"]}
    assert cats == {"NEW", "FIXED", "PERSISTENT", "SEVERITY_CHANGED"}
    print(f"[cmp-api] 对比完成 -> {result['counts']} "
          f"hash={result['comparison_hash'][:16]}")


def test_compare_baseline_rejections_distinct(client):
    # 基线不存在 -> 400 BASELINE_NOT_FOUND
    r = _compare(client, NEW, "nope-id")
    assert r.status_code == 400
    assert r.json()["detail"]["error_code"] == "BASELINE_NOT_FOUND"

    # 基线与当前提交不同源（无同名文件）-> 400 BASELINE_MISMATCH
    other = _audit(client, "contract Other { uint z; }", "Other.sol")
    r2 = _compare(client, NEW, other["task_id"], name="Vault.sol")
    assert r2.status_code == 400
    assert r2.json()["detail"]["error_code"] == "BASELINE_MISMATCH"
    print("[cmp-api] 基线不存在/不同源 -> 400 可区分，未降级")


def test_compare_concurrent_idempotent(client):
    base = _audit(client, BASE)
    ids = []
    barrier = threading.Barrier(8)

    def submit():
        barrier.wait()
        r = _compare(client, NEW, base["task_id"])
        ids.append(r.json()["compare_id"])

    threads = [threading.Thread(target=submit) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(set(ids)) == 1
    body = _wait_compare(client, ids[0])
    assert body["status"] == "SUCCEEDED"
    print(f"[cmp-api] 8 路并发重复对比 -> 单记录 {ids[0][:8]}")


def test_compare_not_found_and_cancel_retry_404(client):
    assert client.get("/comparisons/nope").status_code == 404
    assert client.post("/comparisons/nope/cancel").status_code == 404
    assert client.post("/comparisons/nope/retry").status_code == 404


def test_compare_rejects_malformed_new_version(client):
    base = _audit(client, BASE)
    # 新版本本身是畸形输入：应在创建对比任务前以接入失败码拒绝
    r = client.post(
        "/comparisons",
        data={"baseline_task_id": base["task_id"]},
        files=[("files", ("bad.sol", b"\xff\xfe", "text/plain"))],
    )
    assert r.status_code == 400
    assert r.json()["detail"]["error_code"] == "INVALID_CONTENT"
    print("[cmp-api] 新版本畸形 -> INVALID_CONTENT，对比任务未创建")
