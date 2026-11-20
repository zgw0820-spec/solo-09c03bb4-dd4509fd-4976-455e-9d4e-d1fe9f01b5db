"""/api/summarize 端点冒烟测试:可行、省不下来、校验错误、输入保留由前端负责。"""
import copy
import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
client = TestClient(app)


def load(name):
    return json.loads((EXAMPLES / name).read_text(encoding="utf-8"))


def base_body():
    return {
        "topology": load("topology.json"),
        "routes": load("routes.json"),
        "requirements": load("requirements.json"),
        "switched": [],
    }


def two_details(body, hop="10.0.12.2"):
    body = copy.deepcopy(body)
    body["routes"]["R1"]["before"] = [
        {"prefix": "10.1.0.0/24", "next_hop": hop},
        {"prefix": "10.1.1.0/24", "next_hop": hop},
    ]
    return body


def test_summarize_ok_shape():
    body = two_details(base_body())
    body.update(router="R1", summary_prefix="10.1.0.0/23", next_hop="10.0.12.2")
    r = client.post("/api/summarize", json=body)
    assert r.status_code == 200
    d = r.json()
    assert d["feasible"] is True
    assert d["saved"] == 1
    assert d["router"] == "R1"
    assert len(d["deleted"]) == 2 and len(d["added"]) == 1
    assert d["table_size_before"] == 2 and d["table_size_after"] == 1
    # 可重新上传的路由表:只改 R1.before
    assert d["new_routes"]["R1"]["before"] == [
        {"prefix": "10.1.0.0/23", "next_hop": "10.0.12.2"}
    ]
    assert d["new_routes"]["R2"] == body["routes"]["R2"]


def test_summarize_works_without_requirements():
    body = two_details(base_body())
    body["requirements"] = None
    body.update(router="R1", summary_prefix="10.1.0.0/23", next_hop="10.0.12.2")
    r = client.post("/api/summarize", json=body)
    assert r.status_code == 200
    assert r.json()["feasible"] is True


def test_summarize_cannot_save_returns_200():
    body = base_body()
    body.update(router="R1", summary_prefix="10.1.0.0/24", next_hop="10.0.12.2")
    r = client.post("/api/summarize", json=body)
    assert r.status_code == 200
    d = r.json()
    assert d["feasible"] is False
    assert "没有可删除" in d["message"]


def test_summarize_gap_divergence_evidence():
    body = base_body()
    body["routes"]["R1"]["before"] = [
        {"prefix": "10.1.0.0/24", "next_hop": "10.0.12.2"},
        {"prefix": "10.1.1.0/24", "next_hop": "10.0.12.2"},
        {"prefix": "10.1.3.0/25", "next_hop": "10.0.12.2"},
    ]
    body.update(router="R1", summary_prefix="10.1.0.0/22", next_hop="10.0.12.2")
    r = client.post("/api/summarize", json=body)
    d = r.json()
    assert d["feasible"] is False
    dv = d["divergence"]
    assert dv["address"] == "10.1.2.0"
    assert dv["before_verdict"] == "blackhole"
    assert dv["after_verdict"] == "ok"
    assert dv["before_path"] and dv["after_path"]


def test_summarize_existing_prefix_400():
    body = base_body()
    body.update(router="R3", summary_prefix="10.1.0.0/16", next_hop="198.51.100.2")
    r = client.post("/api/summarize", json=body)
    assert r.status_code == 400
    assert "已存在" in r.json()["detail"]


def test_summarize_bad_next_hop_400():
    body = two_details(base_body())
    body.update(router="R1", summary_prefix="10.1.0.0/23", next_hop="192.0.2.9")
    r = client.post("/api/summarize", json=body)
    assert r.status_code == 400
    assert "直连下一跳" in r.json()["detail"]


def test_summarize_missing_fields_400():
    body = two_details(base_body())
    body.update(router="", summary_prefix="10.1.0.0/23", next_hop="10.0.12.2")
    r = client.post("/api/summarize", json=body)
    assert r.status_code == 400
    assert "选择" in r.json()["detail"]


def test_summarize_switched_uses_after_table():
    body = two_details(base_body(), hop="10.0.14.2")
    body["routes"]["R1"]["after"] = [
        {"prefix": "10.1.0.0/24", "next_hop": "10.0.14.2"},
        {"prefix": "10.1.1.0/24", "next_hop": "10.0.14.2"},
    ]
    body["switched"] = ["R1"]
    body.update(router="R1", summary_prefix="10.1.0.0/23", next_hop="10.0.14.2")
    r = client.post("/api/summarize", json=body)
    d = r.json()
    assert d["feasible"] is True
    assert d["new_routes"]["R1"]["after"] == [
        {"prefix": "10.1.0.0/23", "next_hop": "10.0.14.2"}
    ]
    # before 版不动
    assert d["new_routes"]["R1"]["before"] == body["routes"]["R1"]["before"]
