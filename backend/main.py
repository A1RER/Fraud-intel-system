# backend/main.py
"""
FastAPI 主服务
提供 REST API 接口供前端调用
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from typing import List, Optional
import asyncio
import json
import os
from datetime import datetime
from loguru import logger
import redis.asyncio as aioredis

from backend.models.schemas import AnalysisRequest, AnalysisResponse, AIAnalyzeRequest
from backend.modules.pipeline import AnalysisPipeline
from config.settings import REDIS_URL, REDIS_TASK_TTL, CORS_ORIGINS

TASK_KEY_PREFIX = "fraud:task:"
AI_TASK_KEY_PREFIX = "fraud:aitask:"

redis_client: Optional[aioredis.Redis] = None
pipeline = AnalysisPipeline()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global redis_client
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        await redis_client.ping()
        logger.success("[Redis] 连接成功")
    except Exception as e:
        logger.error(f"[Redis] 连接失败: {e}，异步任务功能将不可用")
        redis_client = None
    yield
    if redis_client:
        await redis_client.close()


app = FastAPI(
    title="涉诈网站智能研判系统 API",
    description="基于开源情报（OSINT）的涉诈网站自动化研判与决策支持",
    version="1.0.0",
    docs_url="/api/docs",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """确保所有未捕获异常返回 JSON 而非 HTML 错误页"""
    logger.error(f"[API] 未捕获异常 {request.url}: {exc}")
    return JSONResponse(
        status_code=500,
        content={"success": False, "error": str(exc)},
    )


@app.get("/")
async def root():
    index = os.path.join(_DIST, "index.html")
    if os.path.isfile(index):
        return FileResponse(index)
    return {"status": "online", "system": "涉诈网站智能研判系统", "version": "1.0.0"}


@app.post("/api/analyze", response_model=AnalysisResponse)
async def analyze_url(request: AnalysisRequest):
    """
    同步分析接口（适合单次快速检测）
    """
    result = await pipeline.run(request)
    return result


@app.post("/api/ai-analyze")
async def ai_analyze(request: AIAnalyzeRequest, background_tasks: BackgroundTasks):
    """
    按需 AI 分析接口 —— 立即返回 task_id，后台执行，通过 /api/ai-task/{task_id} 轮询结果。
    无 Redis 时降级为同步执行（可能超时）。
    """
    import uuid

    if not redis_client:
        # 无 Redis：同步执行（仅本地开发用）
        try:
            gemini_result = await pipeline.run_ai(request.report_id, request.ai_engine)
            return {"success": True, "gemini": gemini_result.model_dump()}
        except Exception as e:
            logger.error(f"[AI] 按需分析失败: {e}")
            return {"success": False, "error": str(e)}

    task_id = f"AITASK-{uuid.uuid4().hex[:8].upper()}"
    _redis = redis_client

    async def _run():
        try:
            gemini_result = await pipeline.run_ai(request.report_id, request.ai_engine)
            payload = json.dumps({"status": "done", "success": True,
                                  "gemini": gemini_result.model_dump()})
        except Exception as e:
            logger.error(f"[AI] 后台任务失败: {e}")
            payload = json.dumps({"status": "done", "success": False, "error": str(e)})
        await _redis.set(f"{AI_TASK_KEY_PREFIX}{task_id}", payload, ex=REDIS_TASK_TTL)

    background_tasks.add_task(_run)
    return {"task_id": task_id, "status": "queued"}


@app.get("/api/ai-task/{task_id}")
async def get_ai_task(task_id: str):
    """轮询 AI 分析后台任务结果"""
    if not redis_client:
        raise HTTPException(status_code=503, detail="Redis 不可用")
    data = await redis_client.get(f"{AI_TASK_KEY_PREFIX}{task_id}")
    if data is None:
        return {"task_id": task_id, "status": "pending"}
    return json.loads(data)


@app.post("/api/analyze/async")
async def analyze_url_async(request: AnalysisRequest, background_tasks: BackgroundTasks):
    """
    异步分析接口（适合批量任务，立即返回 task_id）
    """
    if not redis_client:
        raise HTTPException(status_code=503, detail="Redis 不可用，异步任务功能已禁用")

    import uuid
    task_id = f"TASK-{uuid.uuid4().hex[:8].upper()}"

    _redis = redis_client  # 局部引用，已经过上方 None 守卫

    async def run_task():
        assert _redis is not None
        try:
            result = await pipeline.run(request)
            await _redis.set(
                f"{TASK_KEY_PREFIX}{task_id}",
                result.model_dump_json(),
                ex=REDIS_TASK_TTL,
            )
        except Exception as e:
            logger.error(f"[Task] {task_id} 执行失败: {e}")
            await _redis.set(
                f"{TASK_KEY_PREFIX}{task_id}",
                json.dumps({"success": False, "error": str(e)}),
                ex=REDIS_TASK_TTL,
            )

    background_tasks.add_task(run_task)
    return {"task_id": task_id, "status": "queued", "message": "分析任务已提交"}


@app.get("/api/task/{task_id}")
async def get_task_result(task_id: str):
    """查询异步任务结果"""
    if not redis_client:
        raise HTTPException(status_code=503, detail="Redis 不可用")

    data = await redis_client.get(f"{TASK_KEY_PREFIX}{task_id}")
    if data is None:
        return {"task_id": task_id, "status": "pending", "message": "任务仍在处理中"}
    return {"task_id": task_id, "status": "done", "result": json.loads(data)}


@app.post("/api/batch")
async def batch_analyze(urls: List[str]):
    """批量分析（并发执行）"""
    tasks = [
        pipeline.run(AnalysisRequest(url=url))
        for url in urls[:10]  # 限制最多10个
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return {
        "total": len(urls),
        "results": [
            r if isinstance(r, dict) else {"error": str(r)}
            for r in results
        ]
    }


@app.get("/api/health")
async def health_check():
    redis_ok = False
    task_count = 0
    if redis_client:
        try:
            redis_ok = await redis_client.ping()
            task_count = len(await redis_client.keys(f"{TASK_KEY_PREFIX}*"))
        except Exception:
            pass
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "redis": "connected" if redis_ok else "disconnected",
        "task_queue_size": task_count,
    }


# ── 托管 React 前端静态文件 ──────────────────────────────────────
# npm run build 会把前端打包到 web/dist/
_DIST = os.path.join(os.path.dirname(os.path.dirname(__file__)), "web", "dist")
if os.path.isdir(_DIST):
    # 挂载 /assets 等静态资源
    app.mount("/assets", StaticFiles(directory=os.path.join(_DIST, "assets")), name="assets")

    # 所有非 /api 路径都返回 index.html，让 React 路由接管
    @app.get("/{full_path:path}")
    async def serve_frontend(_full_path: str):
        index = os.path.join(_DIST, "index.html")
        return FileResponse(index)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
