"""版本对比 HTTP API 端到端测试。"""
import importlib
import threading

import pytest
from fastapi.testclient import TestClient

BASE = """
contract Vault {
    mapping(address => uint) balances;
    function withdraw() public {
        uint amount = balances[msg.sender];
        msg.sender.call{value: amount}("");
        balances[msg.sender] = 0;
    }
    function leak() public { msg.sender.send(1); }
}
"""
CUR = """
contract Vault {
    mapping(address => uint) balances;
    function withdraw() public {
        uint amount = balances[msg.sender];
        require(msg.sender.call{value: amount}(""));
    }
    function leak() public { msg.sender.send(1); }
    function evil(address t) public { t.delegatecall(""); }
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


def _upload(client, path, files):
    return client.post(
        path,
        files=[("files", (name, content, "text/plain")) for name, content in files],
    )


def _wait(client, task_id, timeout=10.0):
    import time
    end = time.time() + timeout
    while time.time() < end:
        body = client.get(f"/audits/{task_id}").json()
        if body["status"] in ("SUCCEEDED", "FAILED", "CANCELLED", "TIMEOUT"):
            return body
        time.sleep(0.02)
    raise AssertionError("任务未终态")


def _baseline(client):
    r = _upload(client, "/audits", [("Vault.sol", BASE)])
    assert r.status_code == 202
    tid = r.json()["task_id"]
    body = _wait(client, tid)
    assert body["status"] == "SUCCEEDED"
    return tid


def test_api_compare_categories(client):
    base_id = _baseline(client)
    r = _upload(client, f"/audits/{base_id}/compare", [("Vault.sol", CUR)])
    assert r.status_code == 202, r.text
    task = r.json()
    assert task["kind"] == "diff"
    assert task["baseline_task_id"] == base_id
    body = _wait(client, task["task_id"])
    diff = body["diff"]
    assert diff["baseline_task_id"] == base_id
    assert diff["baseline_fingerprint"] and diff["current_fingerprint"]
    assert diff["counts"]["NEW"] == 1
    assert diff["counts"]["FIXED"] == 1
    assert diff["counts"]["PERSISTING"] == 1
    cats = [e["category"] for e in diff["entries"]]
    assert cats == sorted(cats, key={
        "NEW": 0, "FIXED": 1, "PERSISTING": 2, "SEVERITY_CHANGED": 3
    }.get)
    print(f"[api-diff] 对比结论 {diff['counts']} diff_hash={diff['diff_hash'][:16]}")


def test_api_compare_baseline_errors(client):
    # 基线不存在
    r = _upload(client, "/audits/nope/compare", [("Vault.sol", CUR)])
    assert r.status_code == 400
    assert r.json()["detail"]["error_code"] == "BASELINE_NOT_FOUND"

    # 基线存在但对不上
    base_id = _baseline(client)
    r = _upload(client, f"/audits/{base_id}/compare",
                [("Other.sol", "contract Other { uint z; }")])
    assert r.status_code == 400
    assert r.json()["detail"]["error_code"] == "BASELINE_UNRELATED"

    # 新版本自身畸形仍是接入错误
    r = _upload(client, f"/audits/{base_id}/compare", [])
    assert r.status_code == 400
    assert r.json()["detail"]["error_code"] == "SOURCE_MISSING"
    print("[api-diff] 基线/接入错误均被明确拒绝")


def test_api_compare_idempotent_concurrent(client):
    base_id = _baseline(client)
    first = _upload(client, f"/audits/{base_id}/compare",
                    [("Vault.sol", CUR)]).json()["task_id"]
    ids = []

    def submit():
        ids.append(_upload(
            client, f"/audits/{base_id}/compare", [("Vault.sol", CUR)]
        ).json()["task_id"])

    threads = [threading.Thread(target=submit) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert set(ids) == {first}
    body = _wait(client, first)
    assert body["status"] == "SUCCEEDED"
    print(f"[api-diff] 8 路并发重复对比 -> 单任务 {first[:8]}")


def test_api_compare_separate_baselines(client):
    # 两条不同基线，同一新版本 -> 两个独立对比任务
    b1 = _baseline(client)
    other = """
contract Wallet {
    mapping(address => uint) vault;
    function pay(address r) public { r.delegatecall(""); vault[r] = 1; }
}
"""
    r2 = _upload(client, "/audits", [("Wallet.sol", other)])
    b2 = _wait(client, r2.json()["task_id"])["task_id"]

    cur_both = [("Vault.sol", CUR), ("Wallet.sol", other)]
    d1 = _upload(client, f"/audits/{b1}/compare", cur_both).json()["task_id"]
    d2 = _upload(client, f"/audits/{b2}/compare", cur_both).json()["task_id"]
    assert d1 != d2
    r1, r2b = _wait(client, d1), _wait(client, d2)
    assert r1["diff"]["baseline_task_id"] == b1
    assert r2b["diff"]["baseline_task_id"] == b2
    assert r1["diff"]["diff_hash"] != r2b["diff"]["diff_hash"]
    print("[api-diff] 不同基线独立结论，互不复用")


SEV_BASE = """
contract Vault {
    function leak() public { msg.sender.send(1); }
}
"""
SEV_CUR = """
contract Vault {
    function leak() public { msg.sender.call(""); }
}
"""


def test_api_compare_severity_change(client):
    base_id = _baseline_simple(client, SEV_BASE)
    r = _upload(client, f"/audits/{base_id}/compare", [("Vault.sol", SEV_CUR)])
    assert r.status_code == 202, r.text
    body = _wait(client, r.json()["task_id"])
    diff = body["diff"]
    assert diff["counts"]["SEVERITY_CHANGED"] == 1
    assert diff["counts"]["NEW"] == 0 and diff["counts"]["FIXED"] == 0
    e = diff["entries"][0]
    assert e["category"] == "SEVERITY_CHANGED"
    assert e["baseline_severity"] == "LOW"
    assert e["current_severity"] == "MEDIUM"
    assert e["baseline_finding"]["severity"] == "LOW"
    assert e["current_finding"]["severity"] == "MEDIUM"
    print(f"[api-diff] 严重程度变化 LOW->MEDIUM -> {e['category']}")


def _baseline_simple(client, src):
    r = _upload(client, "/audits", [("Vault.sol", src)])
    assert r.status_code == 202
    return _wait(client, r.json()["task_id"])["task_id"]
