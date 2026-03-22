# backend/main.py
"""
FastAPI 主服务
提供 REST API 接口供前端调用
"""
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from typing import Dict, List
import asyncio
from datetime import datetime
from loguru import logger

from backend.models.schemas import AnalysisRequest, AnalysisResponse
from backend.modules.pipeline import AnalysisPipeline

app = FastAPI(
    title="涉诈网站智能研判系统 API",
    description="基于开源情报（OSINT）的涉诈网站自动化研判与决策支持",
    version="1.0.0",
    docs_url="/api/docs",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

pipeline = AnalysisPipeline()

# 内存任务存储（生产环境替换为 Redis）
task_store: Dict[str, AnalysisResponse] = {}


@app.get("/")
async def root():
    return {"status": "online", "system": "涉诈网站智能研判系统", "version": "1.0.0"}


@app.post("/api/analyze", response_model=AnalysisResponse)
async def analyze_url(request: AnalysisRequest):
    """
    同步分析接口（适合单次快速检测）
    """
    result = await pipeline.run(request)
    return result


@app.post("/api/analyze/async")
async def analyze_url_async(request: AnalysisRequest, background_tasks: BackgroundTasks):
    """
    异步分析接口（适合批量任务，立即返回 task_id）
    """
    import uuid
    task_id = f"TASK-{uuid.uuid4().hex[:8].upper()}"
    
    async def run_task():
        result = await pipeline.run(request)
        task_store[task_id] = result
    
    background_tasks.add_task(run_task)
    return {"task_id": task_id, "status": "queued", "message": "分析任务已提交"}


@app.get("/api/task/{task_id}")
async def get_task_result(task_id: str):
    """查询异步任务结果"""
    if task_id not in task_store:
        return {"task_id": task_id, "status": "pending", "message": "任务仍在处理中"}
    return {"task_id": task_id, "status": "done", "result": task_store[task_id]}


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
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "task_queue_size": len(task_store),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
