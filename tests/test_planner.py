"""核心规划逻辑的自测。

覆盖交付前核对项:
- 同轮不同完成顺序全部安全(枚举同轮所有子集)
- 中途续排(部分设备已换后重新规划仍能安全换完)
- 失败状态:断路 / 环路 / 错出口 的识别与逐跳路径输出

内置示例场景(建新路 → 切换 → 拆旧路):
    旧路径 R1→R2→R3→E1,新路径 R1→R4→R5→E2,入口 R1,允许出口 {E1,E2}。
    R1 换表前 R2/R3 必须留旧表,R1 换表后 R4/R5 必须已就绪,
    因此最少 3 轮:{R4,R5} → {R1} → {R2,R3}。
"""
import itertools
import json
from pathlib import Path

import pytest

from app.planner import (
    VERDICT_BLACKHOLE,
    VERDICT_LOOP,
    VERDICT_WRONG_EGRESS,
    InputError,
    build_model,
    compute_plan,
    representative_addresses,
    state_failures,
)

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def load_example():
    def load(name):
        return json.loads((EXAMPLES / name).read_text(encoding="utf-8"))

    return load("topology.json"), load("routes.json"), load("requirements.json")


@pytest.fixture()
def model():
    topo, routes, reqs = load_example()
    return build_model(topo, routes, reqs)


def all_subsets(items):
    items = list(items)
    for r in range(len(items) + 1):
        for combo in itertools.combinations(items, r):
            yield frozenset(combo)


# --------------------------------------------------------------- 正常规划

def test_example_plan_is_three_rounds(model):
    result = compute_plan(model, set())
    assert result.status == "ok"
    # 建新路(R4,R5 装表)→ 切换(R1)→ 拆旧路(R2,R3 清表),最少 3 轮
    assert [sorted(r) for r in result.rounds] == [["R4", "R5"], ["R1"], ["R2", "R3"]]
    assert sorted(itertools.chain.from_iterable(result.rounds)) == model.routers


def test_plan_cannot_be_two_rounds(model):
    """2 轮在数学上不可能:R1 与任何设备同轮都会留下不安全的中间状态。"""
    # 与 R1 同轮且 R4 未先换完 => 子集 {R1} 断路;R2/R3 先于 R1 换 => 断路
    assert state_failures(model, frozenset({"R1"}))   # R1 先换,R4 未就绪
    assert state_failures(model, frozenset({"R2"}))   # R2 先清表,旧路断
    assert state_failures(model, frozenset({"R2", "R3"}))  # 旧路先拆完,入口还没切
    # 而正确的 3 轮计划确实存在(上一用例),故最少轮次 = 3


def test_same_round_any_completion_order_is_safe(model):
    """同轮无论哪几台先完成,所有中间状态都必须安全。"""
    result = compute_plan(model, set())
    assert result.status == "ok"
    done = set(result.switched)
    for round_routers in result.rounds:
        # 枚举本轮的所有完成子集(含"一台都没换完"和"全部换完")
        for subset in all_subsets(round_routers):
            state = done | subset
            failures = state_failures(model, state)
            assert failures == [], f"状态 {sorted(state)} 不安全: {failures[0].verdict}"
        done |= set(round_routers)
    assert done == set(model.routers)


def test_wrong_order_is_caught(model):
    """sanity:先换 R1(新路未就绪)确实断路,证明检查不是空转。"""
    failures = state_failures(model, frozenset({"R1"}))
    assert failures and all(f.verdict == VERDICT_BLACKHOLE for f in failures)


def test_final_state_safe(model):
    assert state_failures(model, frozenset(model.routers)) == []


# --------------------------------------------------------------- 中途续排

def test_replan_after_partial_round(model):
    """第一轮只换完一台(R4)就续排,仍能安全换完,且后续每步乱序安全。"""
    first = compute_plan(model, set())
    assert first.status == "ok"
    partial = {"R4"}  # 现场只换完第一轮中的 R4,R5 还没换
    replanned = compute_plan(model, partial)
    assert replanned.status == "ok"
    assert replanned.switched == ["R4"]
    done = set(partial)
    for round_routers in replanned.rounds:
        for subset in all_subsets(round_routers):
            assert state_failures(model, done | subset) == []
        done |= set(round_routers)
    assert done == set(model.routers)
    # 续排轮次不超过从头规划的轮次(第一轮被打散也不亏轮次)
    assert len(replanned.rounds) <= len(first.rounds)


def test_replan_after_full_round_keeps_minimality(model):
    """整轮换完后续排,剩余轮次应正好少一轮。"""
    first = compute_plan(model, set())
    done = set(first.rounds[0])
    replanned = compute_plan(model, done)
    assert replanned.status == "ok"
    assert len(replanned.rounds) == len(first.rounds) - 1


def test_replan_every_prefix_state(model):
    """沿计划的任意前缀状态(含同轮任意子集)续排,都能安全到达全部换完。"""
    plan = compute_plan(model, set())
    done = set()
    for round_routers in plan.rounds:
        for subset in all_subsets(round_routers):
            state = done | subset
            result = compute_plan(model, state)
            assert result.status == "ok", f"从 {sorted(state)} 续排失败"
        done |= set(round_routers)
    assert compute_plan(model, done).rounds == []


# --------------------------------------------------------------- 失败状态

def test_current_wrong_egress(model):
    """允许出口只留 E2 时,当前(全旧表)流量走 E1,报'当前不通/错出口'。"""
    topo, routes, reqs = load_example()
    reqs["requirements"][0]["allowed_egress"] = ["E2"]
    m = build_model(topo, routes, reqs)
    result = compute_plan(m, set())
    assert result.status == "failed"
    assert result.reason == "current_unsafe"
    assert result.failure_state == []
    f = next(f for f in result.failures if f.verdict == VERDICT_WRONG_EGRESS)
    assert f.egress == "E1"
    assert [h.router for h in f.path][:3] == ["R1", "R2", "R3"]  # 逐跳路径


def test_unreachable_because_of_loop(model):
    """R4 新表指回 R1(配置错误),任何顺序都绕不开环路,报'无法安全换完'。"""
    topo, routes, reqs = load_example()
    routes["R4"]["after"] = [{"prefix": "10.1.0.0/16", "next_hop": "10.0.14.1"}]
    m = build_model(topo, routes, reqs)
    result = compute_plan(m, set())
    assert result.status == "failed"
    assert result.reason == "unreachable"
    assert result.failure_state is not None
    loops = [f for f in result.failures if f.verdict == VERDICT_LOOP]
    assert loops, "失败证据里应包含环路"
    # 环路路径的终点应回到路径中已出现过的路由器
    path_routers = [h.router for h in loops[0].path]
    assert len(path_routers) != len(set(path_routers))


def test_blackhole_when_route_missing(model):
    """R5 新表删掉目标路由,R1 切过去后流量无匹配,报断路。"""
    topo, routes, reqs = load_example()
    routes["R5"]["after"] = []
    m = build_model(topo, routes, reqs)
    result = compute_plan(m, set())
    assert result.status == "failed"
    assert result.reason == "unreachable"
    blackholes = [f for f in result.failures if f.verdict == VERDICT_BLACKHOLE]
    assert blackholes
    last = blackholes[0].path[-1]
    assert last.router == "R5"
    assert last.matched_prefix is None


def test_blackhole_unresolvable_next_hop(model):
    """下一跳不在任何链路/出口子网内,也判断路。"""
    topo, routes, reqs = load_example()
    routes["R5"]["after"] = [{"prefix": "10.1.0.0/16", "next_hop": "192.0.2.254"}]
    m = build_model(topo, routes, reqs)
    result = compute_plan(m, set())
    assert result.status == "failed"
    blackholes = [f for f in result.failures if f.verdict == VERDICT_BLACKHOLE]
    assert blackholes
    assert blackholes[0].path[-1].matched_prefix == "10.1.0.0/16"


# --------------------------------------------------------------- 等价类划分

def test_representative_addresses_split_by_more_specific(model):
    """R3 表里钉了 10.1.0.0/24,目标 /16 应被切成两个等价类。"""
    import ipaddress

    reps = representative_addresses(model, ipaddress.IPv4Network("10.1.0.0/16"))
    assert [str(a) for a in reps] == ["10.1.0.0", "10.1.1.0"]


def test_pinned_more_specific_consistent_across_states(model):
    """被钉在 E1 的 /24 在旧路径状态下走 E1,切完后 /24 类也按新表走。"""
    # 初始状态:/24 类在 R3 命中被钉的 /24 → E1
    assert state_failures(model, frozenset()) == []
    # 全换完:/24 类在 R1 命中 /16 → 新路 → E2(允许),仍安全
    assert state_failures(model, frozenset(model.routers)) == []


# --------------------------------------------------------------- 输入校验

def test_router_limit(model):
    topo, routes, reqs = load_example()
    for i in range(6, 10):  # 加到 9 台
        routes[f"RX{i}"] = {"before": [], "after": []}
    with pytest.raises(InputError, match="超过上限"):
        build_model(topo, routes, reqs)


def test_unknown_egress_in_requirement():
    topo, routes, reqs = load_example()
    reqs["requirements"][0]["allowed_egress"] = ["E9"]
    with pytest.raises(InputError, match="不存在的出口"):
        build_model(topo, routes, reqs)


def test_unknown_switched_device(model):
    with pytest.raises(InputError, match="已换设备"):
        compute_plan(model, {"R9"})
