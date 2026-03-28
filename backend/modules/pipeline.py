# backend/modules/pipeline.py
"""
情报分析流水线主控器
采集 -> 特征提取 -> WRAS评分 -> 决策输出
"""
import os
import uuid
import time
from datetime import datetime, timezone
from typing import List, Optional
from collections import OrderedDict
from loguru import logger

from backend.models.schemas import (
    AnalysisRequest, AnalysisResponse, IntelReport, DisposalPlan, GeminiAnalysis
)
from backend.modules.osint_collector import OSINTCollector
from backend.modules.feature_engineer import FeatureEngineer
from backend.modules.wras_engine import WRASEngine
from backend.modules.gemini_analyzer import (
    GeminiContentAnalyzer, GeminiVisionAnalyzer, GeminiReportGenerator
)
from config.settings import DISPOSAL_PLANS, GEMINI_MODEL


class AnalysisPipeline:
    """
    情报分析流水线

    流程：
    URL → OSINT采集 → 特征工程 → WRAS评分 → 决策输出 → 结构化报告
    """
    _ai_cache: OrderedDict = OrderedDict()
    _CACHE_MAX = 100

    def __init__(self):
        self.wras_engine = WRASEngine()

    def _cache_for_ai(self, report_id: str, raw_intel, report_context: dict):
        """缓存分析上下文供后续按需 AI 分析"""
        AnalysisPipeline._ai_cache[report_id] = {
            "page_text": raw_intel.page_text or "",
            "page_title": raw_intel.page_title or "",
            "screenshot_b64": raw_intel.screenshot_b64 or "",
            "report_context": report_context,
        }
        while len(AnalysisPipeline._ai_cache) > self._CACHE_MAX:
            AnalysisPipeline._ai_cache.popitem(last=False)

    async def run_ai(self, report_id: str, ai_engine: str) -> GeminiAnalysis:
        """按需运行 AI 分析（复用已缓存的 OSINT 数据，不重复采集）"""
        cached = AnalysisPipeline._ai_cache.get(report_id)
        if not cached:
            raise ValueError("分析缓存已过期，请重新执行基础分析")

        page_text = cached["page_text"]
        page_title = cached["page_title"]
        screenshot_b64 = cached["screenshot_b64"]
        report_context = dict(cached["report_context"])

        ai_start = time.time()

        content_result = {}
        try:
            content_result = GeminiContentAnalyzer.analyze(
                page_text, page_title, engine=ai_engine,
            )
        except Exception as e:
            logger.warning(f"[AI] 内容分析失败: {e}")

        vision_result = {}
        try:
            vision_result = GeminiVisionAnalyzer.analyze(
                screenshot_b64, engine=ai_engine,
            )
        except Exception as e:
            logger.warning(f"[AI] 视觉分析失败: {e}")

        report_context["ai_content_score"] = content_result.get("risk_score", 0)
        report_context["ai_fraud_types"] = content_result.get("fraud_types", [])
        report_context["ai_evidence"] = content_result.get("key_evidence", [])

        try:
            ai_report_text, report_provider = GeminiReportGenerator.generate(
                report_context, engine=ai_engine,
            )
        except Exception as e:
            ai_report_text = f"⚠️ AI 报告生成失败：{e}"
            report_provider = ""

        content_provider = content_result.get("_provider", "")
        actual_provider = report_provider or content_provider or ""

        logger.success(f"[PIPELINE] 按需 AI 分析完成 [{actual_provider}]")
        return GeminiAnalysis(
            model_name=actual_provider,
            ai_elapsed_s=round(time.time() - ai_start, 2),
            content_risk_score=content_result.get("risk_score", 0.0),
            fraud_types=content_result.get("fraud_types", []),
            key_evidence=content_result.get("key_evidence", []),
            risk_indicators=content_result.get("risk_indicators", []),
            content_reasoning=content_result.get("reasoning", ""),
            visual_risk_score=vision_result.get("visual_risk_score", 0.0),
            is_phishing=vision_result.get("is_phishing", False),
            impersonates=vision_result.get("impersonates"),
            visual_features=vision_result.get("visual_features", []),
            visual_description=vision_result.get("description", ""),
            ai_report=ai_report_text,
        )

    async def run(self, request: AnalysisRequest) -> AnalysisResponse:
        report_id = f"RPT-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6].upper()}"
        start_time = time.time()
        
        logger.info(f"[PIPELINE] 开始分析 | report_id={report_id} | url={request.url}")
        
        try:
            # 运行时读取 API Key（避免模块缓存导致空值）
            gemini_api_key = os.getenv("GEMINI_API_KEY", "")
            deepseek_api_key = os.getenv("DEEPSEEK_API_KEY", "")
            ai_engine = request.ai_engine  # auto / gemini / deepseek

            # 阶段一：OSINT 采集
            logger.info("[PIPELINE] 阶段1/5: OSINT 情报采集")
            raw_intel = await OSINTCollector.collect(request.url)

            # 阶段二：AI 内容 + 视觉分析（结果融入特征工程）
            content_result, vision_result = {}, {}
            engine_available = (
                (ai_engine in ("auto", "gemini") and gemini_api_key) or
                (ai_engine in ("auto", "deepseek") and deepseek_api_key)
            )
            if engine_available:
                logger.info(f"[PIPELINE] 阶段2/5: AI 内容与视觉分析 (engine={ai_engine})")
                try:
                    content_result = GeminiContentAnalyzer.analyze(
                        raw_intel.page_text or "", raw_intel.page_title or "",
                        engine=ai_engine,
                    )
                    vision_result = GeminiVisionAnalyzer.analyze(
                        raw_intel.screenshot_b64 or "", engine=ai_engine,
                    )
                except Exception as e:
                    logger.warning(f"[PIPELINE] AI 分析失败（降级为纯规则）: {e}")

            # 阶段三：特征工程（融合 AI 结果）
            logger.info("[PIPELINE] 阶段3/5: 特征提取与信号增强")
            features = FeatureEngineer.extract(
                raw_intel, request.extra_keywords,
                gemini_content=content_result, gemini_vision=vision_result,
            )

            # 阶段四：WRAS 评分
            logger.info("[PIPELINE] 阶段4/5: WRAS 风险评分计算")
            source_count = 1 + (1 if raw_intel.search_snippets else 0) + \
                           (1 if raw_intel.social_mentions else 0) + \
                           (1 if raw_intel.complaint_count > 0 else 0)
            if content_result.get("risk_score", 0) > 0:
                source_count += 1  # AI 也算一个情报源，提升置信度

            wras_result = self.wras_engine.score(
                features,
                collected_at=raw_intel.collected_at,
                source_count=source_count,
            )

            # 阶段五：决策支持 + AI 报告
            logger.info("[PIPELINE] 阶段5/5: 生成决策处置预案与 AI 报告")
            disposal_data = DISPOSAL_PLANS[wras_result.risk_level.value]
            disposal = DisposalPlan(**disposal_data)

            # 构建报告上下文（始终构建，供即时或按需 AI 分析使用）
            report_context = {
                "url": request.url,
                "domain": raw_intel.domain,
                "wras_score": wras_result.final_score,
                "risk_level": wras_result.risk_level.value,
                "confidence": wras_result.confidence_coeff,
                "domain_age_days": raw_intel.domain_age_days,
                "icp_record": raw_intel.icp_record,
                "whois_privacy": raw_intel.whois_privacy,
                "ssl_valid": raw_intel.ssl_valid,
                "ssl_self_signed": raw_intel.ssl_self_signed,
                "server_ip": raw_intel.server_ip,
                "server_country": raw_intel.server_country,
                "server_isp": raw_intel.server_isp,
                "is_cdn": raw_intel.is_cdn,
                "redirect_count": len(raw_intel.redirect_chain),
                "blacklist_hit": raw_intel.blacklist_hit,
                "complaint_count": raw_intel.complaint_count,
                "search_snippets": raw_intel.search_snippets,
                "ai_content_score": content_result.get("risk_score", 0),
                "ai_fraud_types": content_result.get("fraud_types", []),
                "ai_evidence": content_result.get("key_evidence", []),
                "score_breakdown": wras_result.score_breakdown,
                "feature_contrib": wras_result.feature_contrib,
            }

            # 缓存供后续按需 AI 分析
            self._cache_for_ai(report_id, raw_intel, report_context)

            gemini_result = None
            ai_start = time.time()
            if engine_available:
                try:
                    ai_report_text, report_provider = GeminiReportGenerator.generate(report_context, engine=ai_engine)

                    content_provider = content_result.get("_provider", "")
                    actual_provider = report_provider or content_provider or GEMINI_MODEL

                    gemini_result = GeminiAnalysis(
                        model_name=actual_provider,
                        ai_elapsed_s=round(time.time() - ai_start, 2),
                        content_risk_score=content_result.get("risk_score", 0.0),
                        fraud_types=content_result.get("fraud_types", []),
                        key_evidence=content_result.get("key_evidence", []),
                        risk_indicators=content_result.get("risk_indicators", []),
                        content_reasoning=content_result.get("reasoning", ""),
                        visual_risk_score=vision_result.get("visual_risk_score", 0.0),
                        is_phishing=vision_result.get("is_phishing", False),
                        impersonates=vision_result.get("impersonates"),
                        visual_features=vision_result.get("visual_features", []),
                        visual_description=vision_result.get("description", ""),
                        ai_report=ai_report_text,
                    )
                    logger.success(f"[PIPELINE] AI 报告生成完成 [{actual_provider}]")
                except Exception as e:
                    logger.warning(f"[PIPELINE] AI 报告生成失败: {e}")

            # 组装报告
            report = IntelReport(
                report_id=report_id,
                url=request.url,
                raw_intel=raw_intel,
                features=features,
                wras=wras_result,
                disposal=disposal,
                gemini=gemini_result,
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
