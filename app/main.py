"""备份专网出口切换 · 换表轮次规划器 Web 服务。"""
from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .planner import InputError, build_model, compute_plan
from .summarizer import summarize

BASE_DIR = Path(__file__).resolve().parent
EXAMPLES_DIR = BASE_DIR.parent / "examples"

app = FastAPI(title="换表轮次规划器", version="1.0.0")


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return (BASE_DIR / "static" / "index.html").read_text(encoding="utf-8")


@app.get("/api/example")
async def example() -> JSONResponse:
    """返回内置示例,便于页面一键填充。"""
    def load(name: str):
        return json.loads((EXAMPLES_DIR / name).read_text(encoding="utf-8"))

    return JSONResponse({
        "topology": load("topology.json"),
        "routes": load("routes.json"),
        "requirements": load("requirements.json"),
    })


@app.post("/api/plan")
async def plan(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except json.JSONDecodeError:
        return JSONResponse({"detail": "请求体必须是 JSON"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"detail": "请求体必须是 JSON 对象"}, status_code=400)
    try:
        model = build_model(
            body.get("topology"), body.get("routes"), body.get("requirements")
        )
        switched = body.get("switched") or []
        if not isinstance(switched, list):
            raise InputError("switched 必须是路由器名数组")
        result = compute_plan(model, {str(x) for x in switched})
    except InputError as exc:
        return JSONResponse({"detail": str(exc)}, status_code=400)
    return JSONResponse(result.as_dict())


@app.post("/api/summarize")
async def summarize_route(request: Request) -> JSONResponse:
    """试算在指定设备新增一条汇总路由后最多能净省多少表项。"""
    try:
        body = await request.json()
    except json.JSONDecodeError:
        return JSONResponse({"detail": "请求体必须是 JSON"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"detail": "请求体必须是 JSON 对象"}, status_code=400)
    try:
        # 试算只依赖拓扑与路由表;保通要求可选,缺失时 build_model 跳过校验
        model = build_model(
            body.get("topology"), body.get("routes"), body.get("requirements")
        )
        switched = body.get("switched") or []
        if not isinstance(switched, list):
            raise InputError("switched 必须是路由器名数组")
        router = body.get("router")
        if not router:
            raise InputError("请选择要试加汇总路由的设备")
        prefix = body.get("summary_prefix")
        if not prefix:
            raise InputError("请填写拟加的 IPv4 汇总前缀")
        next_hop = body.get("next_hop")
        if not next_hop:
            raise InputError("请填写直连下一跳")
        result = summarize(
            model, {str(x) for x in switched}, str(router),
            str(prefix), str(next_hop), routes_payload=body.get("routes"),
        )
    except InputError as exc:
        return JSONResponse({"detail": str(exc)}, status_code=400)
    return JSONResponse(result.as_dict())
