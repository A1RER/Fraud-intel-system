# backend/modules/pipeline.py
"""
情报分析流水线主控器
采集 -> 特征提取 -> WRAS评分 -> 决策输出
"""
import uuid
import time
from datetime import datetime, timezone
from typing import List, Optional
from loguru import logger

from backend.models.schemas import (
    AnalysisRequest, AnalysisResponse, IntelReport, DisposalPlan
)
from backend.modules.osint_collector import OSINTCollector
from backend.modules.feature_engineer import FeatureEngineer
from backend.modules.wras_engine import WRASEngine
from config.settings import DISPOSAL_PLANS


class AnalysisPipeline:
    """
    情报分析流水线
    
    流程：
    URL → OSINT采集 → 特征工程 → WRAS评分 → 决策输出 → 结构化报告
    """
    
    def __init__(self):
        self.wras_engine = WRASEngine()
    
    async def run(self, request: AnalysisRequest) -> AnalysisResponse:
        report_id = f"RPT-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6].upper()}"
        start_time = time.time()
        
        logger.info(f"[PIPELINE] 开始分析 | report_id={report_id} | url={request.url}")
        
        try:
            # 阶段一：OSINT 采集
            logger.info("[PIPELINE] 阶段1/4: OSINT 情报采集")
            raw_intel = await OSINTCollector.collect(request.url)
            
            # 阶段二：特征工程
            logger.info("[PIPELINE] 阶段2/4: 特征提取与信号增强")
            features = FeatureEngineer.extract(raw_intel, request.extra_keywords)
            
            # 阶段三：WRAS 评分
            logger.info("[PIPELINE] 阶段3/4: WRAS 风险评分计算")
            source_count = 1 + (1 if raw_intel.search_snippets else 0) + \
                           (1 if raw_intel.social_mentions else 0) + \
                           (1 if raw_intel.complaint_count > 0 else 0)
            
            wras_result = self.wras_engine.score(
                features,
                collected_at=raw_intel.collected_at,
                source_count=source_count,
            )
            
            # 阶段四：决策支持
            logger.info("[PIPELINE] 阶段4/4: 生成决策处置预案")
            disposal_data = DISPOSAL_PLANS[wras_result.risk_level.value]
            disposal = DisposalPlan(**disposal_data)
            
            # 组装报告
            report = IntelReport(
                report_id=report_id,
                url=request.url,
                raw_intel=raw_intel,
                features=features,
                wras=wras_result,
                disposal=disposal,
            )
            
            elapsed = round(time.time() - start_time, 2)
            logger.success(
                f"[PIPELINE] 分析完成 | report_id={report_id} | "
                f"score={wras_result.final_score:.1f} | "
                f"level={wras_result.risk_level} | elapsed={elapsed}s"
            )
            
            return AnalysisResponse(
                success=True,
                report_id=report_id,
                report=report,
                elapsed_s=elapsed,
            )
            
        except Exception as e:
            elapsed = round(time.time() - start_time, 2)
            logger.error(f"[PIPELINE] 分析失败 | report_id={report_id} | error={e}")
            return AnalysisResponse(
                success=False,
                report_id=report_id,
                error=str(e),
                elapsed_s=elapsed,
            )
