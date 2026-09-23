"""端到端 API 测试：提交、查询、取消、重试、畸形输入的可区分拒绝。"""
import importlib
import os
import threading

import pytest
from fastapi.testclient import TestClient

VULN = """
contract Vault {
    mapping(address => uint) balances;
    function withdraw() public {
        uint amount = balances[msg.sender];
        msg.sender.call{value: amount}("");
        balances[msg.sender] = 0;
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


def _submit(client, files):
    return client.post(
        "/audits",
        files=[("files", (name, content, "text/plain")) for name, content in files],
    )


def _wait(client, task_id, timeout=10.0):
    import time
    end = time.time() + timeout
    while time.time() < end:
        r = client.get(f"/audits/{task_id}")
        assert r.status_code == 200
        body = r.json()
        if body["status"] in ("SUCCEEDED", "FAILED", "CANCELLED", "TIMEOUT"):
            return body
        time.sleep(0.02)
    raise AssertionError("任务未在期限内进入终态")


def test_submit_and_get_report(client):
    r = _submit(client, [("Vault.sol", VULN)])
    assert r.status_code == 202
    task_id = r.json()["task_id"]
    body = _wait(client, task_id)
    assert body["status"] == "SUCCEEDED"
    report = body["report"]
    assert report["clean"] is False
    f = report["findings"][0]
    assert set(f["rule_ids"]) == {"REENTRANCY", "DANGEROUS_EXTERNAL_CALL"}
    print(f"[api] 提交审计 -> {task_id[:8]} findings={len(report['findings'])} "
          f"hash={report['report_hash'][:16]} 首条={f['finding_id']}:{f['severity']}")


def test_api_dedup_and_concurrent(client):
    r1 = _submit(client, [("Vault.sol", VULN)]).json()
    results = []

    def submit():
        results.append(_submit(client, [("Vault.sol", VULN)]).json()["task_id"])

    threads = [threading.Thread(target=submit) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert set(results) == {r1["task_id"]}
    done = _wait(client, r1["task_id"])
    print(f"[api] 8 路并发重复提交 -> 单任务 {r1['task_id'][:8]} "
          f"status={done['status']}")


def test_api_rejects_malformed_with_distinct_codes(client):
    cases = [
        ([], "SOURCE_MISSING"),
        ([("A.sol", b"\xff\xfe\x00")], "INVALID_CONTENT"),
        ([("A.sol", "garbage text")], "INVALID_CONTENT"),
        ([("B.sol", 'import "./Nope.sol";\ncontract B {}')], "IMPORT_UNRESOLVABLE"),
    ]
    seen = set()
    for files, expected in cases:
        r = _submit(client, files)
        assert r.status_code == 400, (files, r.text)
        code = r.json()["detail"]["error_code"]
        assert code == expected
        seen.add(code)
        print(f"[api] 拒绝畸形输入 -> {code}")
    assert len(seen) == 3


def test_api_cancel_and_retry_not_found(client):
    assert client.get("/audits/nope").status_code == 404
    assert client.post("/audits/nope/cancel").status_code == 404
    assert client.post("/audits/nope/retry").status_code == 404


def test_api_clean_conclusion(client):
    safe = "contract C { uint public x; function inc() public { x += 1; } }\n"
    r = _submit(client, [("C.sol", safe)])
    body = _wait(client, r.json()["task_id"])
    assert body["report"]["clean"] is True
    assert body["report"]["findings"] == []
    print(f"[api] 未命中规则 -> clean=True hash={body['report']['report_hash'][:16]}")
