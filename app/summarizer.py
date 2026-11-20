"""静态路由汇总试算核心逻辑。

场景
----
静态路由表快满时,值班员拟在某台路由器上新增一条 IPv4 汇总(aggregate)前缀,
指向一个直连下一跳,并删掉该设备表中被汇总覆盖的更具体表项。本模块在**不动现网**
的前提下试算:

1. 按"已换设备"勾选状态取全网每台路由器的当前在用表(before / after);
2. 校验汇总前缀必须是所选设备当前表的新前缀,且范围内更具体表项不超过 10 条;
3. 枚举可删表项的全部组合(≤10 条 → ≤1024 种),对每种组合:
   - 构造修改后的表(新增汇总 + 删除候选);
   - 把汇总前缀按全网当前表切分为等价区间,逐类取代表地址;
   - 从**每一台路由器**出发逐跳仿真(最长前缀匹配),要求修改前后的转发结论
     完全一致:同为某个出口的正常转发(出口名相同),或同为断路 / 环路;
     不一致时把修改前/后两条逐跳路径作为分歧证据返回;
4. 取通过校验的、删除条数最多的组合,给出增删明细与净省表项数。

等价区间划分保证"汇总范围内任一地址"都被覆盖;汇总前缀跨过无路由区间时,
这些区间在修改前后同为无匹配断路,自然纳入比较。
"""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from itertools import combinations

from .planner import (
    VERDICT_BLACKHOLE,
    VERDICT_LOOP,
    VERDICT_OK,
    Hop,
    InputError,
    Model,
    Route,
    _longest_prefix_match,
    _v4addr,
    _v4net,
)

MAX_MORE_SPECIFIC = 10


# ---------------------------------------------------------------- 数据结构

@dataclass
class Divergence:
    """一次转发结论不一致的证据。"""
    ingress: str
    address: str
    before_verdict: str
    after_verdict: str
    before_egress: str | None
    after_egress: str | None
    before_path: list[Hop]
    after_path: list[Hop]

    def as_dict(self) -> dict:
        return {
            "ingress": self.ingress,
            "address": self.address,
            "before_verdict": self.before_verdict,
            "after_verdict": self.after_verdict,
            "before_egress": self.before_egress,
            "after_egress": self.after_egress,
            "before_path": [h.as_dict() for h in self.before_path],
            "after_path": [h.as_dict() for h in self.after_path],
        }


@dataclass
class SummaryResult:
    feasible: bool
    message: str
    router: str | None = None
    summary_prefix: str | None = None
    next_hop: str | None = None
    candidates: list[dict] = field(default_factory=list)
    deleted: list[dict] = field(default_factory=list)
    added: list[dict] = field(default_factory=list)
    saved: int = 0
    table_size_before: int = 0
    table_size_after: int = 0
    checked_addresses: list[str] = field(default_factory=list)
    divergence: Divergence | None = None
    new_routes: dict | None = None       # 可重新上传的完整路由表 JSON
    switched: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "feasible": self.feasible,
            "message": self.message,
            "router": self.router,
            "summary_prefix": self.summary_prefix,
            "next_hop": self.next_hop,
            "candidates": self.candidates,
            "deleted": self.deleted,
            "added": self.added,
            "saved": self.saved,
            "table_size_before": self.table_size_before,
            "table_size_after": self.table_size_after,
            "checked_addresses": self.checked_addresses,
            "divergence": self.divergence.as_dict() if self.divergence else None,
            "new_routes": self.new_routes,
            "switched": self.switched,
        }


# ---------------------------------------------------------------- 工具函数

def active_table(model: Model, router: str, switched: frozenset[str]) -> list[Route]:
    """按勾选状态取一台路由器的当前在用表。"""
    tbl = model.tables[router]
    return tbl.after if router in switched else tbl.before


def current_tables(model: Model, switched: frozenset[str]) -> dict[str, list[Route]]:
    return {r: list(active_table(model, r, switched)) for r in model.routers}


def equivalence_addresses(tables: dict[str, list[Route]],
                          target: ipaddress.IPv4Network) -> list[ipaddress.IPv4Address]:
    """把 target 按所有当前表中与之重叠的前缀切成等价区间,每区取首个地址。

    同一区间内任一地址在任意路由器上的最长前缀匹配结果都相同;
    没有任何表项覆盖的区间也会保留,用于验证"无路由区间"行为不变。
    """
    lo0, hi0 = int(target.network_address), int(target.broadcast_address) + 1
    cuts = {lo0, hi0}
    for table in tables.values():
        for rt in table:
            net = rt.network
            if not net.overlaps(target):
                continue
            lo = max(int(net.network_address), lo0)
            hi = min(int(net.broadcast_address) + 1, hi0)
            if lo < hi:
                cuts.add(lo)
                cuts.add(hi)
    cuts = sorted(cuts)
    return [ipaddress.IPv4Address(cuts[i]) for i in range(len(cuts) - 1)]


def trace_with(model: Model, tables: dict[str, list[Route]],
               ingress: str, addr: ipaddress.IPv4Address):
    """用给定表集合(而非 model 内的 before/after)仿真逐跳转发。"""
    path: list[Hop] = []
    visited: set[str] = set()
    cur = ingress
    while True:
        if cur in visited:
            path.append(Hop(cur, None, None, "router", cur))
            return VERDICT_LOOP, None, path
        visited.add(cur)
        rt = _longest_prefix_match(tables[cur], addr)
        if rt is None:
            path.append(Hop(cur, None, None, "none", None))
            return VERDICT_BLACKHOLE, None, path
        target = None
        for net, dest in model.resolve[cur]:
            if rt.next_hop in net:
                target = dest
                break
        if target is None:
            path.append(Hop(cur, str(rt.network), str(rt.next_hop), "none", None))
            return VERDICT_BLACKHOLE, None, path
        kind, name = target
        path.append(Hop(cur, str(rt.network), str(rt.next_hop), kind, name))
        if kind == "egress":
            return VERDICT_OK, name, path
        cur = name


def _route_dict(rt: Route) -> dict:
    return {"prefix": str(rt.network), "next_hop": str(rt.next_hop)}


# ---------------------------------------------------------------- 主流程

def summarize(model: Model, switched: set[str], router: str,
              summary_prefix: str, next_hop: str,
              routes_payload: dict | None = None) -> SummaryResult:
    """试算在 router 上新增汇总前缀并删除更具体表项后的最大可省表项。

    routes_payload 为原始上传的路由表 JSON,用于生成"只替换所选设备当前版"
    的可重新上传文件;为 None 时用模型内数据重建。
    """
    unknown = switched - set(model.routers)
    if unknown:
        raise InputError(f"已换设备不在路由器清单中: {sorted(unknown)}")
    if router not in model.tables:
        raise InputError(f"所选设备不存在: {router}")
    switched = frozenset(switched)

    summary = _v4net(str(summary_prefix), "汇总前缀")
    if summary.prefixlen == 0:
        raise InputError("汇总前缀不能是默认路由 0.0.0.0/0")
    hop = _v4addr(str(next_hop), "直连下一跳")

    tables = current_tables(model, switched)
    selected = tables[router]

    # 下一跳必须是该设备的直连下一跳(落在链路子网或本机出口子网内)
    if not any(hop in net for net, _ in model.resolve[router]):
        raise InputError(
            f"下一跳 {hop} 不是 {router} 的直连下一跳"
            "(不在任何直连链路子网或本机出口子网内)"
        )

    # 汇总前缀必须是该表的新前缀
    if any(rt.network == summary for rt in selected):
        raise InputError(f"汇总前缀 {summary} 已存在于 {router} 的当前表中,必须是新前缀")

    # 范围内的更具体表项(真子集;同前缀已在上一步排除)
    candidate_idx = [i for i, rt in enumerate(selected) if rt.network.subnet_of(summary)]
    candidates = [selected[i] for i in candidate_idx]
    if len(candidates) > MAX_MORE_SPECIFIC:
        raise InputError(
            f"汇总前缀 {summary} 范围内有 {len(candidates)} 条更具体表项,"
            f"超过上限 {MAX_MORE_SPECIFIC} 条"
        )

    checked = equivalence_addresses(tables, summary)
    checked_str = [str(a) for a in checked]
    size_before = len(selected)

    def fail(msg: str, divergence: Divergence | None = None) -> SummaryResult:
        return SummaryResult(
            feasible=False, message=msg, router=router,
            summary_prefix=str(summary), next_hop=str(hop),
            candidates=[_route_dict(rt) for rt in candidates],
            checked_addresses=checked_str, divergence=divergence,
            switched=sorted(switched),
        )

    if not candidates:
        return fail(
            f"省不下来:汇总前缀 {summary} 范围内没有可删除的更具体表项,"
            "新增 1 条反而多占 1 个表项。"
        )

    summary_route = Route(summary, hop)

    # 修改前的基线追踪只算一次,所有删除组合复用(组合数最多 1024)
    baseline: dict[tuple[str, ipaddress.IPv4Address], tuple] = {}
    for ingress in model.routers:
        for addr in checked:
            baseline[(ingress, addr)] = trace_with(model, tables, ingress, addr)

    def verify(remove: frozenset[int]) -> Divergence | None:
        """构造修改后的表,逐入口 × 逐等价区间比对转发结论。"""
        modified = dict(tables)
        new_selected = [rt for i, rt in enumerate(selected) if i not in remove]
        new_selected.append(summary_route)
        modified[router] = new_selected
        for ingress in model.routers:
            for addr in checked:
                v0, e0, p0 = baseline[(ingress, addr)]
                v1, e1, p1 = trace_with(model, modified, ingress, addr)
                if (v0, e0) != (v1, e1):
                    return Divergence(
                        ingress=ingress, address=str(addr),
                        before_verdict=v0, after_verdict=v1,
                        before_egress=e0, after_egress=e1,
                        before_path=p0, after_path=p1,
                    )
        return None

    # 枚举全部删除组合,优先尝试删得多的;记录首个分歧作为"省不下来"的证据
    best_remove: frozenset[int] | None = None
    first_divergence: Divergence | None = None
    n = len(candidates)
    for size in range(n, 0, -1):
        for combo in combinations(range(n), size):
            remove = frozenset(candidate_idx[k] for k in combo)
            divergence = verify(remove)
            if divergence is None:
                best_remove = remove
                break
            if first_divergence is None:
                first_divergence = divergence
        if best_remove is not None:
            break

    if best_remove is None:
        return fail(
            f"省不下来:汇总前缀 {summary} 范围内 {n} 条更具体表项的任意删除组合都会改变"
            "至少一处转发结论(实际出口或断路/环路),下面给出一处不一致证据。",
            first_divergence,
        )

    deleted_routes = [selected[i] for i in sorted(best_remove)]
    new_selected = [rt for i, rt in enumerate(selected) if i not in best_remove]
    new_selected.append(summary_route)
    saved = len(deleted_routes) - 1

    if saved <= 0:
        return fail(
            f"省不下来:最多只能安全删除 {len(deleted_routes)} 条,"
            f"新增汇总 1 条后净省 {saved} 个表项。"
        )

    # ---- 生成可重新上传的路由表 JSON:只替换所选设备的当前版
    version = "after" if router in switched else "before"
    if routes_payload is not None and isinstance(routes_payload.get(router), dict):
        new_routes = json.loads(json.dumps(routes_payload, ensure_ascii=False))
        new_routes[router][version] = [_route_dict(rt) for rt in new_selected]
    else:
        new_routes = {}
        for r in model.routers:
            new_routes[r] = {
                "before": [_route_dict(rt) for rt in model.tables[r].before],
                "after": [_route_dict(rt) for rt in model.tables[r].after],
            }
        new_routes[router][version] = [_route_dict(rt) for rt in new_selected]

    return SummaryResult(
        feasible=True,
        message=(
            f"可以净省 {saved} 个表项:在 {router} 新增汇总 {summary} → {hop},"
            f"同时删除 {len(deleted_routes)} 条更具体表项"
            f"(表项 {size_before} → {len(new_selected)})。"
            "已按全网当前表逐跳核验,汇总范围内任一地址的实际出口及断路/环路结论均与修改前一致。"
        ),
        router=router, summary_prefix=str(summary), next_hop=str(hop),
        candidates=[_route_dict(rt) for rt in candidates],
        deleted=[_route_dict(rt) for rt in deleted_routes],
        added=[_route_dict(summary_route)],
        saved=saved,
        table_size_before=size_before,
        table_size_after=len(new_selected),
        checked_addresses=checked_str,
        new_routes=new_routes,
        switched=sorted(switched),
    )
