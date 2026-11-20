"""备份专网出口切换的换表轮次规划核心逻辑。

模型
----
- 拓扑:路由器之间有点到点链路(带子网),部分路由器挂着"出口"(外部下一跳子网)。
- 每台路由器有换版前(before)/换版后(after)两张 IPv4 静态路由表,整表切换。
- 保通要求:入口路由器 + 目标 CIDR + 允许的出口集合。
- 状态:已切换路由器集合。某状态安全 <=> 对所有要求、目标网段内任一地址,
  从入口按最长前缀匹配逐跳转发,最终都落在允许的出口(无断路/环路/错出口)。
- 一轮:一个状态超集,要求该轮中"任意完成顺序"下的所有中间状态都安全
  (即子立方体内全部状态安全)。用 BFS 求最少轮次。
"""
from __future__ import annotations

import ipaddress
from collections import deque
from dataclasses import dataclass, field

MAX_ROUTERS = 8
MAX_ROUTES_PER_TABLE = 500

VERDICT_OK = "ok"
VERDICT_BLACKHOLE = "blackhole"      # 断路:无匹配路由或下一跳无法解析
VERDICT_LOOP = "loop"                # 环路:转发回到已路过的路由器
VERDICT_WRONG_EGRESS = "wrong_egress"  # 错出口:落点不在允许出口集合内

VERDICT_ZH = {
    VERDICT_OK: "正常",
    VERDICT_BLACKHOLE: "断路",
    VERDICT_LOOP: "环路",
    VERDICT_WRONG_EGRESS: "错出口",
}


# ---------------------------------------------------------------- 数据模型

@dataclass
class Route:
    network: ipaddress.IPv4Network
    next_hop: ipaddress.IPv4Address


@dataclass
class RouterTables:
    before: list[Route]
    after: list[Route]


@dataclass
class Link:
    a: str
    b: str
    network: ipaddress.IPv4Network


@dataclass
class Egress:
    name: str
    router: str
    network: ipaddress.IPv4Network


@dataclass
class Requirement:
    name: str
    ingress: str
    target: ipaddress.IPv4Network
    allowed_egress: set[str]


@dataclass
class Model:
    routers: list[str]                     # 固定顺序,作为状态位序号
    links: list[Link]
    egresses: list[Egress]
    tables: dict[str, RouterTables]
    requirements: list[Requirement]
    # 每台路由器:[(子网, ("router", 邻居) 或 ("egress", 出口名))],按前缀长降序
    resolve: dict[str, list[tuple[ipaddress.IPv4Network, tuple[str, str]]]] = field(default_factory=dict)


class InputError(ValueError):
    """输入数据校验错误,返回 400。"""


def _v4net(value: str, what: str) -> ipaddress.IPv4Network:
    try:
        net = ipaddress.IPv4Network(value, strict=False)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as exc:
        raise InputError(f"{what} 不是合法 IPv4 CIDR: {value!r}") from exc
    return net


def _v4addr(value: str, what: str) -> ipaddress.IPv4Address:
    try:
        return ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as exc:
        raise InputError(f"{what} 不是合法 IPv4 地址: {value!r}") from exc


def _parse_routes(items, what: str) -> list[Route]:
    if not isinstance(items, list):
        raise InputError(f"{what} 必须是数组")
    if len(items) > MAX_ROUTES_PER_TABLE:
        raise InputError(f"{what} 路由条数超过上限 {MAX_ROUTES_PER_TABLE}")
    routes = []
    for i, item in enumerate(items):
        if not isinstance(item, dict) or "prefix" not in item or "next_hop" not in item:
            raise InputError(f"{what}[{i}] 需要 prefix 和 next_hop 字段")
        routes.append(Route(
            network=_v4net(str(item["prefix"]), f"{what}[{i}].prefix"),
            next_hop=_v4addr(str(item["next_hop"]), f"{what}[{i}].next_hop"),
        ))
    return routes


def build_model(topology: dict, routes: dict, requirements: dict) -> Model:
    """把上传的三个 JSON 对象校验并组装成模型。"""
    if not isinstance(topology, dict):
        raise InputError("拓扑必须是 JSON 对象")
    if not isinstance(routes, dict):
        raise InputError("路由表必须是 JSON 对象")
    if not isinstance(requirements, dict):
        raise InputError("保通要求必须是 JSON 对象")

    # ---- 链路
    links = []
    for i, item in enumerate(topology.get("links", [])):
        try:
            a, b, subnet = item["a"], item["b"], item["subnet"]
        except (KeyError, TypeError) as exc:
            raise InputError(f"拓扑 links[{i}] 需要 a、b、subnet 字段") from exc
        if a == b:
            raise InputError(f"拓扑 links[{i}] 两端不能是同一台路由器: {a}")
        links.append(Link(str(a), str(b), _v4net(str(subnet), f"links[{i}].subnet")))

    # ---- 出口
    egresses = []
    seen_egress = set()
    for i, item in enumerate(topology.get("egresses", [])):
        try:
            name, router, subnet = item["name"], item["router"], item["subnet"]
        except (KeyError, TypeError) as exc:
            raise InputError(f"拓扑 egresses[{i}] 需要 name、router、subnet 字段") from exc
        name = str(name)
        if name in seen_egress:
            raise InputError(f"出口名重复: {name}")
        seen_egress.add(name)
        egresses.append(Egress(name, str(router), _v4net(str(subnet), f"egresses[{i}].subnet")))

    # ---- 路由表
    tables: dict[str, RouterTables] = {}
    for name, versions in routes.items():
        name = str(name)
        if not isinstance(versions, dict) or "before" not in versions or "after" not in versions:
            raise InputError(f"路由表 {name} 需要 before 和 after 两个字段")
        tables[name] = RouterTables(
            before=_parse_routes(versions["before"], f"{name}.before"),
            after=_parse_routes(versions["after"], f"{name}.after"),
        )

    # ---- 路由器集合 = 路由表出现的设备(链路和出口必须落在其中)
    routers = sorted(tables.keys())
    if not routers:
        raise InputError("路由表为空,至少需要 1 台路由器")
    if len(routers) > MAX_ROUTERS:
        raise InputError(f"路由器数量 {len(routers)} 超过上限 {MAX_ROUTERS}")
    rset = set(routers)
    for lk in links:
        for side in (lk.a, lk.b):
            if side not in rset:
                raise InputError(f"链路 {lk.a}-{lk.b} 引用了没有路由表的路由器: {side}")
    for eg in egresses:
        if eg.router not in rset:
            raise InputError(f"出口 {eg.name} 挂在没有路由表的路由器上: {eg.router}")

    # ---- 保通要求
    reqs = []
    items = requirements.get("requirements")
    if not isinstance(items, list) or not items:
        raise InputError("保通要求 requirements 必须是非空数组")
    for i, item in enumerate(items):
        try:
            name = str(item.get("name", f"req{i+1}"))
            ingress = str(item["ingress"])
            target = _v4net(str(item["target"]), f"requirements[{i}].target")
            allowed = item["allowed_egress"]
        except (KeyError, TypeError) as exc:
            raise InputError(f"requirements[{i}] 需要 ingress、target、allowed_egress 字段") from exc
        if ingress not in rset:
            raise InputError(f"要求 {name} 的入口路由器不存在: {ingress}")
        if not isinstance(allowed, list) or not allowed:
            raise InputError(f"要求 {name} 的 allowed_egress 必须是非空数组")
        allowed = {str(x) for x in allowed}
        unknown = allowed - seen_egress
        if unknown:
            raise InputError(f"要求 {name} 引用了不存在的出口: {sorted(unknown)}")
        reqs.append(Requirement(name, ingress, target, allowed))

    # ---- 每台路由器的下一跳解析表(链路对端 + 本机出口),最长前缀优先
    resolve: dict[str, list[tuple[ipaddress.IPv4Network, tuple[str, str]]]] = {r: [] for r in routers}
    for lk in links:
        resolve[lk.a].append((lk.network, ("router", lk.b)))
        resolve[lk.b].append((lk.network, ("router", lk.a)))
    for eg in egresses:
        resolve[eg.router].append((eg.network, ("egress", eg.name)))
    for r in routers:
        resolve[r].sort(key=lambda x: x[0].prefixlen, reverse=True)

    return Model(routers=routers, links=links, egresses=egresses,
                 tables=tables, requirements=reqs, resolve=resolve)


# ------------------------------------------------------- 目标网段等价类划分

def representative_addresses(model: Model, target: ipaddress.IPv4Network) -> list[ipaddress.IPv4Address]:
    """把目标 CIDR 按所有路由表中与之重叠的前缀切成等价区间。

    同一区间内所有地址,在任何路由器的任何一张表里的最长前缀匹配结果都相同,
    因此每类取一个代表地址验证即可覆盖"网段内任一地址"。
    """
    lo0, hi0 = int(target.network_address), int(target.broadcast_address) + 1
    cuts = {lo0, hi0}
    for tbl in model.tables.values():
        for table in (tbl.before, tbl.after):
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


# ------------------------------------------------------------- 转发仿真

@dataclass
class Hop:
    router: str
    matched_prefix: str | None
    next_hop: str | None
    to_kind: str        # "router" | "egress" | "none"
    to_name: str | None

    def as_dict(self) -> dict:
        return {
            "router": self.router,
            "matched_prefix": self.matched_prefix,
            "next_hop": self.next_hop,
            "to_kind": self.to_kind,
            "to_name": self.to_name,
        }


@dataclass
class Trace:
    verdict: str
    egress: str | None
    path: list[Hop]


def _longest_prefix_match(table: list[Route], addr: ipaddress.IPv4Address) -> Route | None:
    best = None
    for rt in table:
        if addr in rt.network and (best is None or rt.network.prefixlen > best.network.prefixlen):
            best = rt
    return best


def trace(model: Model, state: frozenset[str], ingress: str,
          addr: ipaddress.IPv4Address) -> Trace:
    """在给定状态(已切换集合)下,从 ingress 仿真 addr 的逐跳转发。"""
    path: list[Hop] = []
    visited: set[str] = set()
    cur = ingress
    while True:
        if cur in visited:
            path.append(Hop(cur, None, None, "router", cur))
            return Trace(VERDICT_LOOP, None, path)
        visited.add(cur)
        tbl = model.tables[cur]
        table = tbl.after if cur in state else tbl.before
        rt = _longest_prefix_match(table, addr)
        if rt is None:
            path.append(Hop(cur, None, None, "none", None))
            return Trace(VERDICT_BLACKHOLE, None, path)
        target = None
        for net, dest in model.resolve[cur]:
            if rt.next_hop in net:
                target = dest
                break
        if target is None:
            path.append(Hop(cur, str(rt.network), str(rt.next_hop), "none", None))
            return Trace(VERDICT_BLACKHOLE, None, path)
        kind, name = target
        path.append(Hop(cur, str(rt.network), str(rt.next_hop), kind, name))
        if kind == "egress":
            return Trace(VERDICT_OK, name, path)
        cur = name


@dataclass
class Failure:
    requirement: str
    ingress: str
    target_address: str
    verdict: str
    egress: str | None
    path: list[Hop]

    def as_dict(self) -> dict:
        return {
            "requirement": self.requirement,
            "ingress": self.ingress,
            "target_address": self.target_address,
            "verdict": self.verdict,
            "verdict_zh": VERDICT_ZH[self.verdict],
            "egress": self.egress,
            "path": [h.as_dict() for h in self.path],
        }


def state_failures(model: Model, state: frozenset[str], max_failures: int = 20) -> list[Failure]:
    """列出该状态下所有保通要求的违约项(空列表 = 安全)。"""
    failures: list[Failure] = []
    for req in model.requirements:
        for addr in representative_addresses(model, req.target):
            tr = trace(model, state, req.ingress, addr)
            if tr.verdict == VERDICT_OK and tr.egress in req.allowed_egress:
                continue
            verdict = tr.verdict if tr.verdict != VERDICT_OK else VERDICT_WRONG_EGRESS
            failures.append(Failure(req.name, req.ingress, str(addr),
                                    verdict, tr.egress, tr.path))
            if len(failures) >= max_failures:
                return failures
    return failures


# ------------------------------------------------------------- 轮次规划

@dataclass
class PlanResult:
    status: str                 # "ok" | "failed"
    reason: str | None          # "current_unsafe" | "unreachable"
    rounds: list[list[str]]
    switched: list[str]
    failure_state: list[str] | None
    failures: list[Failure]
    message: str

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "reason": self.reason,
            "rounds": self.rounds,
            "switched": self.switched,
            "failure_state": self.failure_state,
            "failures": [f.as_dict() for f in self.failures],
            "message": self.message,
        }


def compute_plan(model: Model, switched: set[str]) -> PlanResult:
    """从已切换集合出发,求最少轮次的安全换表计划。"""
    routers = model.routers
    idx = {r: i for i, r in enumerate(routers)}
    unknown = switched - set(routers)
    if unknown:
        raise InputError(f"已换设备不在路由器清单中: {sorted(unknown)}")
    n = len(routers)
    full = (1 << n) - 1
    start = 0
    for r in switched:
        start |= 1 << idx[r]

    def names(mask: int) -> list[str]:
        return [routers[i] for i in range(n) if mask >> i & 1]

    # 1) 预计算所有状态的安全性(2^8 = 256,每个状态做转发仿真)
    safe = [False] * (1 << n)
    fail_cache: list[list[Failure]] = [[] for _ in range(1 << n)]
    for mask in range(1 << n):
        f = state_failures(model, frozenset(names(mask)))
        fail_cache[mask] = f
        safe[mask] = not f

    def failures_of(mask: int) -> list[Failure]:
        return fail_cache[mask]

    if not safe[start]:
        return PlanResult(
            status="failed", reason="current_unsafe", rounds=[],
            switched=names(start), failure_state=names(start),
            failures=failures_of(start),
            message="当前状态已不满足保通要求,请先修复再安排换表。",
        )

    # 2) 子立方体有效性:round m -> sup 合法 <=> [m, sup] 间所有状态安全
    subcube_memo: dict[tuple[int, int], bool] = {}

    def subcube_safe(m: int, sup: int) -> bool:
        key = (m, sup)
        if key in subcube_memo:
            return subcube_memo[key]
        if m == sup:
            subcube_memo[key] = safe[m]
            return safe[m]
        bit = (sup ^ m) & -(sup ^ m)  # 取 sup 比 m 多出的某一个比特
        ok = subcube_safe(m, sup ^ bit) and subcube_safe(m | bit, sup)
        subcube_memo[key] = ok
        return ok

    # 3) BFS 求最少轮次;邻居按新增路由器数量降序,同轮次下优先大轮
    prev: dict[int, tuple[int, int] | None] = {start: None}
    queue = deque([start])
    while queue:
        m = queue.popleft()
        if m == full:
            break
        remaining = full ^ m
        supersets = []
        sub = remaining
        while sub:
            supersets.append(m | sub)
            sub = (sub - 1) & remaining
        supersets.sort(key=lambda s: (-bin(s ^ m).count("1"), names(s ^ m)))
        for sup in supersets:
            if sup in prev:
                continue
            if subcube_safe(m, sup):
                prev[sup] = (m, sup)
                queue.append(sup)

    if full in prev:
        rounds = []
        cur = full
        while cur != start:
            m, sup = prev[cur]
            rounds.append(names(sup ^ m))
            cur = m
        rounds.reverse()
        return PlanResult(
            status="ok", reason=None, rounds=rounds,
            switched=names(start), failure_state=None, failures=[],
            message=f"共 {len(rounds)} 轮;同轮内任意完成顺序均安全。",
        )

    # 4) 不可达:找一个"挡路"的失败状态作为证据
    #    在可达安全集合的边界上,找加一个路由器就违约的状态
    frontier_fail: int | None = None
    if not safe[full]:
        frontier_fail = full  # 全部换完本身就不安全
    else:
        for m in sorted(prev, key=lambda x: -bin(x).count("1")):
            for i in range(n):
                bit = 1 << i
                if not m & bit and not safe[m | bit]:
                    frontier_fail = m | bit
                    break
            if frontier_fail is not None:
                break
    if frontier_fail is None:  # 理论兜底
        frontier_fail = full
    return PlanResult(
        status="failed", reason="unreachable", rounds=[],
        switched=names(start), failure_state=names(frontier_fail),
        failures=failures_of(frontier_fail),
        message="从当前状态出发,不存在能安全换完全部设备的顺序;"
                "下面给出一个必然经过的失败状态作为证据。",
    )
