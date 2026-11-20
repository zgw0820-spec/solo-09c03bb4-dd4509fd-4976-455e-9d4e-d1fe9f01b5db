"""汇总路由试算核心逻辑的自测。

覆盖交付前核对项:
- 试算按"已换设备"勾选状态取当前用表(before/after);
- 汇总前缀必须是新前缀;范围内更具体表项 ≤10;下一跳必须直连;
- 可行时返回最大可删子集、增删明细、净省数、只替换所选设备当前版的新路由表;
- 试算明细嵌套(/23 内套 /24)时等价区间划分正确;
- 汇总跨过无路由区间:间隙在修改前后结论不一致则拦截,下游同为断路则放行;
- 断路 / 环路 / 正常出口三类结论在修改前后逐跳一致才放行,否则给出分歧证据;
- 从任一路由器入口都参与核验;省不下来时返回 feasible=False 而非抛错。
"""
import copy
import json
from pathlib import Path

import pytest

from app.planner import InputError, build_model
from app.summarizer import MAX_MORE_SPECIFIC, equivalence_addresses, summarize

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def load_example():
    def load(name):
        return json.loads((EXAMPLES / name).read_text(encoding="utf-8"))

    return load("topology.json"), load("routes.json"), load("requirements.json")


@pytest.fixture()
def example():
    return load_example()


def build(topo, routes, reqs):
    return build_model(topo, routes, reqs if reqs is not None else None)


def two_detail_routes(routes, hop="10.0.12.2", routers=("R1",)):
    """把指定设备的 before 表换成两条相邻 /24,指向同一台邻居。"""
    routes = copy.deepcopy(routes)
    for r in routers:
        routes[r]["before"] = [
            {"prefix": "10.1.0.0/24", "next_hop": hop},
            {"prefix": "10.1.1.0/24", "next_hop": hop},
        ]
    return routes


# --------------------------------------------------------------- 输入校验

def test_summary_prefix_must_be_new(example):
    topo, routes, reqs = example
    m = build(topo, routes, reqs)
    # R3 before 已含 10.1.0.0/16
    with pytest.raises(InputError, match="已存在"):
        summarize(m, set(), "R3", "10.1.0.0/16", "198.51.100.2", routes)


def test_next_hop_must_be_directly_connected(example):
    topo, routes, reqs = example
    routes = two_detail_routes(routes)
    m = build(topo, routes, reqs)
    with pytest.raises(InputError, match="直连下一跳"):
        summarize(m, set(), "R1", "10.1.0.0/23", "192.0.2.9", routes)


def test_more_specific_limit(example):
    topo, routes, reqs = example
    routes = copy.deepcopy(routes)
    routes["R1"]["before"] = [
        {"prefix": f"10.1.{i}.0/24", "next_hop": "10.0.12.2"}
        for i in range(MAX_MORE_SPECIFIC + 1)
    ]
    m = build(topo, routes, reqs)
    with pytest.raises(InputError, match=f"超过上限 {MAX_MORE_SPECIFIC}"):
        summarize(m, set(), "R1", "10.1.0.0/16", "10.0.12.2", routes)


def test_unknown_router_and_switched(example):
    topo, routes, reqs = example
    m = build(topo, routes, reqs)
    with pytest.raises(InputError, match="设备不存在"):
        summarize(m, set(), "R9", "10.1.0.0/23", "10.0.12.2", routes)
    with pytest.raises(InputError, match="已换设备"):
        summarize(m, {"R9"}, "R1", "10.1.0.0/23", "10.0.12.2", routes)


def test_invalid_prefix_and_hop(example):
    topo, routes, reqs = example
    m = build(topo, routes, reqs)
    with pytest.raises(InputError, match="CIDR"):
        summarize(m, set(), "R1", "10.1.0.0/99", "10.0.12.2", routes)
    with pytest.raises(InputError, match="IPv4 地址"):
        summarize(m, set(), "R1", "10.1.0.0/23", "not-an-ip", routes)


# --------------------------------------------------------------- 可行场景

def test_feasible_summary_saves_entries(example):
    topo, routes, reqs = example
    routes = two_detail_routes(routes)
    m = build(topo, routes, reqs)
    r = summarize(m, set(), "R1", "10.1.0.0/23", "10.0.12.2", routes)
    assert r.feasible is True
    assert r.saved == 1                      # 删 2 增 1
    assert len(r.deleted) == 2
    assert r.added == [{"prefix": "10.1.0.0/23", "next_hop": "10.0.12.2"}]
    assert r.table_size_before == 2 and r.table_size_after == 1
    # 等价区间:两个 /24 各一个代表地址
    assert r.checked_addresses == ["10.1.0.0", "10.1.1.0"]


def test_new_routes_only_replaces_selected_current_version(example):
    topo, routes, reqs = example
    routes = two_detail_routes(routes)
    m = build(topo, routes, reqs)
    r = summarize(m, set(), "R1", "10.1.0.0/23", "10.0.12.2", routes)
    new_routes = r.new_routes
    # 未勾选 -> 替换 before;after 及其余设备原样保留
    assert new_routes["R1"]["before"] == [
        {"prefix": "10.1.0.0/23", "next_hop": "10.0.12.2"}
    ]
    assert new_routes["R1"]["after"] == routes["R1"]["after"]
    for other in ("R2", "R3", "R4", "R5"):
        assert new_routes[other] == routes[other]


def test_switched_selection_uses_after_version(example):
    topo, routes, reqs = example
    # R1 after 只有 10.1.0.0/16;在 after 上试加 /24 没有候选 -> 省不下来而非报错
    m = build(topo, routes, reqs)
    r = summarize(m, {"R1"}, "R1", "10.1.0.0/24", "10.0.14.2", routes)
    assert r.feasible is False
    assert r.switched == ["R1"]
    assert "没有可删除" in r.message

    # 可行场景下,新文件应替换 after 版
    routes2 = two_detail_routes(routes)
    routes2["R1"]["after"] = [
        {"prefix": "10.1.0.0/24", "next_hop": "10.0.14.2"},
        {"prefix": "10.1.1.0/24", "next_hop": "10.0.14.2"},
    ]
    m2 = build(topo, routes2, reqs)
    r2 = summarize(m2, {"R1"}, "R1", "10.1.0.0/23", "10.0.14.2", routes2)
    assert r2.feasible is True
    assert r2.new_routes["R1"]["after"] == [
        {"prefix": "10.1.0.0/23", "next_hop": "10.0.14.2"}
    ]
    assert r2.new_routes["R1"]["before"] == routes2["R1"]["before"]


# --------------------------------------------------------------- 明细嵌套

def test_nested_more_specifics_all_removable(example):
    """/23 内套 /24,再加一个相邻 /23,汇总成 /22 后三条全删。"""
    topo, routes, reqs = example
    routes = copy.deepcopy(routes)
    routes["R1"]["before"] = [
        {"prefix": "10.1.0.0/23", "next_hop": "10.0.12.2"},
        {"prefix": "10.1.0.0/24", "next_hop": "10.0.12.2"},
        {"prefix": "10.1.2.0/23", "next_hop": "10.0.12.2"},
    ]
    m = build(topo, routes, reqs)
    r = summarize(m, set(), "R1", "10.1.0.0/22", "10.0.12.2", routes)
    assert r.feasible is True
    assert r.saved == 2
    assert sorted(d["prefix"] for d in r.deleted) == [
        "10.1.0.0/23", "10.1.0.0/24", "10.1.2.0/23",
    ]
    # 嵌套 /24 把 10.1.0.0/23 切成两段,等价地址覆盖到 /25 边界
    assert r.checked_addresses == ["10.1.0.0", "10.1.1.0", "10.1.2.0"]


def test_equivalence_addresses_split_by_nested_prefix(example):
    """汇总范围内的更具体前缀把范围切成等价区间;无路由区间的行为在 gap 用例中验证。"""
    topo, routes, reqs = example
    m = build(topo, routes, reqs)
    import ipaddress
    tables = {r: list(m.tables[r].before) for r in m.routers}
    # /22 完全落在 10.1.0.0/16 内:R3 钉的 /24 把首段切开,共 2 个等价类
    addrs = equivalence_addresses(tables, ipaddress.IPv4Network("10.1.0.0/22"))
    assert [str(a) for a in addrs] == ["10.1.0.0", "10.1.1.0"]


# ----------------------------------------------------- 汇总跨过无路由区间

def test_gap_changes_blackhole_to_forward_is_rejected(example):
    """间隙地址修改前在本机无匹配断路,加汇总后被转发 -> 结论改变,必须拦截。"""
    topo, routes, reqs = example
    routes = copy.deepcopy(routes)
    routes["R1"]["before"] = [
        {"prefix": "10.1.0.0/24", "next_hop": "10.0.12.2"},
        {"prefix": "10.1.1.0/24", "next_hop": "10.0.12.2"},
        {"prefix": "10.1.3.0/25", "next_hop": "10.0.12.2"},
    ]
    m = build(topo, routes, reqs)
    r = summarize(m, set(), "R1", "10.1.0.0/22", "10.0.12.2", routes)
    assert r.feasible is False
    assert r.divergence is not None
    dv = r.divergence
    assert dv.address == "10.1.2.0"
    assert dv.before_verdict == "blackhole" and dv.after_verdict == "ok"
    # 修改前路径末跳是 R1 无匹配;修改后多出汇总匹配
    assert dv.before_path[-1].matched_prefix is None
    assert dv.after_path[0].matched_prefix == "10.1.0.0/22"


def test_gap_allowed_when_downstream_also_blackholes(example):
    """间隙在修改后仍断路(下游无表),结论一致 -> 放行并净省。"""
    topo, routes, reqs = example
    routes = two_detail_routes(routes)
    routes["R2"]["before"] = []   # 流量到 R2 后无匹配,依旧断路
    m = build(topo, routes, reqs)
    r = summarize(m, set(), "R1", "10.1.0.0/22", "10.0.12.2", routes)
    assert r.feasible is True
    assert r.saved == 1
    assert "10.1.2.0" in r.checked_addresses


# ----------------------------------------------------- 断路 / 环路结论一致性

def test_loop_verdict_preserved(example):
    """R1→R2→R1 的环路,汇总同指 R2 时环路结论保持,允许删除。"""
    topo, routes, reqs = example
    routes = two_detail_routes(routes)
    routes["R2"]["before"] = [
        {"prefix": "10.1.0.0/16", "next_hop": "10.0.12.1"}
    ]
    m = build(topo, routes, reqs)
    r = summarize(m, set(), "R1", "10.1.0.0/23", "10.0.12.2", routes)
    assert r.feasible is True
    assert r.saved == 1


def test_diverting_to_other_egress_is_rejected(example):
    """汇总改指另一条已就绪的路,正常出口由 E1 变 E2 -> 拦截并给出分歧。"""
    topo, routes, reqs = example
    routes = two_detail_routes(routes, hop="10.0.12.2")
    # 让新路径 R1→R4→R5→E2 在 before 状态下也已就绪
    routes["R4"]["before"] = [
        {"prefix": "10.1.0.0/16", "next_hop": "10.0.45.2"}
    ]
    routes["R5"]["before"] = [
        {"prefix": "10.1.0.0/16", "next_hop": "198.51.100.6"}
    ]
    m = build(topo, routes, reqs)
    r = summarize(m, set(), "R1", "10.1.0.0/23", "10.0.14.2", routes)
    assert r.feasible is False
    assert r.divergence is not None
    dv = r.divergence
    assert dv.before_verdict == "ok" and dv.after_verdict == "ok"
    assert {dv.before_egress, dv.after_egress} == {"E1", "E2"}


def test_conflicting_next_hops_yields_zero_net_saving(example):
    """两条明细下一跳不同,汇总最多安全删 1 条 -> 净省 0,提示省不下来。"""
    topo, routes, reqs = example
    routes = copy.deepcopy(routes)
    routes["R1"]["before"] = [
        {"prefix": "10.1.0.0/24", "next_hop": "10.0.12.2"},
        {"prefix": "10.1.1.0/24", "next_hop": "10.0.14.2"},
    ]
    m = build(topo, routes, reqs)
    r = summarize(m, set(), "R1", "10.1.0.0/23", "10.0.12.2", routes)
    assert r.feasible is False
    assert "净省 0" in r.message


def test_max_removable_subset_is_chosen(example):
    """4 条 /24 中 1 条指向别处,最大安全子集为 3 条,净省 2。"""
    topo, routes, reqs = example
    routes = copy.deepcopy(routes)
    routes["R1"]["before"] = [
        {"prefix": "10.1.0.0/24", "next_hop": "10.0.12.2"},
        {"prefix": "10.1.1.0/24", "next_hop": "10.0.12.2"},
        {"prefix": "10.1.2.0/24", "next_hop": "10.0.12.2"},
        {"prefix": "10.1.3.0/24", "next_hop": "10.0.14.2"},
    ]
    m = build(topo, routes, reqs)
    r = summarize(m, set(), "R1", "10.1.0.0/22", "10.0.12.2", routes)
    assert r.feasible is True
    assert r.saved == 2
    assert sorted(d["prefix"] for d in r.deleted) == [
        "10.1.0.0/24", "10.1.1.0/24", "10.1.2.0/24",
    ]
    # 未删的异常明细仍在新表里
    new_before = {x["prefix"]: x["next_hop"] for x in r.new_routes["R1"]["before"]}
    assert new_before["10.1.3.0/24"] == "10.0.14.2"
    assert new_before["10.1.0.0/22"] == "10.0.12.2"


def test_no_candidate_means_cannot_save(example):
    topo, routes, reqs = example
    m = build(topo, routes, reqs)
    r = summarize(m, set(), "R1", "10.1.0.0/24", "10.0.12.2", routes)
    assert r.feasible is False
    assert "没有可删除" in r.message


def test_check_runs_from_every_router_ingress(example):
    """分歧只在从别的路由器入口才暴露时,也必须被抓到。"""
    topo, routes, reqs = example
    routes = copy.deepcopy(routes)
    routes["R1"]["before"] = [
        {"prefix": "10.1.0.0/24", "next_hop": "10.0.12.2"},
    ]
    # R2 默认路由回指 R1:间隙地址 R1 加汇总后在 R1↔R2 间成环
    routes["R2"]["before"] = [
        {"prefix": "0.0.0.0/0", "next_hop": "10.0.12.1"},
    ]
    routes["R3"]["before"] = [
        {"prefix": "10.1.0.0/16", "next_hop": "198.51.100.2"},
    ]
    m = build(topo, routes, reqs)
    r = summarize(m, set(), "R1", "10.1.0.0/22", "10.0.12.2", routes)
    assert r.feasible is False
    assert r.divergence is not None
    assert r.divergence.address == "10.1.1.0"
    assert r.divergence.before_verdict == "blackhole"
    assert r.divergence.after_verdict == "loop"


def test_works_without_requirements(example):
    topo, routes, _ = example
    routes = two_detail_routes(routes)
    m = build(topo, routes, None)
    r = summarize(m, set(), "R1", "10.1.0.0/23", "10.0.12.2", routes)
    assert r.feasible is True
    assert r.saved == 1
