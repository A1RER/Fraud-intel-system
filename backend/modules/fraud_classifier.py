# backend/modules/fraud_classifier.py
"""
模块：诈骗类型分类与风险判定
融合话术分析、企业核验、AI 分析结果，输出最终风险判定
"""
from typing import Dict, List, Optional
from loguru import logger

from backend.models.schemas import FraudRiskResult


class FraudClassifier:
    """诈骗类型分类器 + 证据链生成器 + 防范建议"""

    # ── 各分析源权重 ─────────────────────────────────────────────
    WEIGHTS = {
        "text_analysis":  0.45,   # 话术规则分析
        "company_check":  0.20,   # 企业核验
        "ai_analysis":    0.35,   # AI 语义分析
    }

    # ── 防范建议模板 ─────────────────────────────────────────────
    SUGGESTIONS: Dict[str, List[str]] = {
        "付费培训诈骗": [
            "正规公司不会在入职前收取任何费用",
            "要求先缴费再上岗，极大概率是诈骗",
            "可在国家企业信用信息公示系统查询公司资质",
        ],
        "虚假内推诈骗": [
            "真正的内推不需要付费，付费内推基本是骗局",
            "核实内推人身份，要求提供工牌或在职证明",
            "直接去公司官网投递简历更安全",
        ],
        "高薪诱导诈骗": [
            "远超行业平均的薪资承诺通常是诱饵",
            '「零基础高薪」「在家轻松赚」都是典型诈骗话术',
            "先核实公司和岗位的真实性再做决定",
        ],
        "信息盗取诈骗": [
            "入职前不应要求提供银行卡密码、验证码等敏感信息",
            "手持身份证照片可能被用于网贷、开户等违法行为",
            "仅在签订正式劳动合同后才提供必要的个人信息",
        ],
        "_default": [
            "通过正规招聘平台（如 BOSS直聘、智联招聘）投递简历",
            "入职前不向任何单位转账或提供银行卡、验证码",
            "有疑问可拨打 12321 网络不良信息举报热线",
        ],
    }

    @classmethod
    def classify(
        cls,
        text_result: Optional[dict] = None,
        company_result: Optional[dict] = None,
        ai_result: Optional[dict] = None,
        input_type: str = "recruitment",
    ) -> FraudRiskResult:
        """
        融合多源分析结果，输出最终 FraudRiskResult

        参数:
            text_result:    RecruitmentAnalyzer.analyze() 的输出
            company_result: CompanyChecker.check() 的输出
            ai_result:      RecruitmentAnalyzer.ai_analyze() 的输出
            input_type:     输入类型
        """
        scores: Dict[str, float] = {}
        fraud_type_weights: Dict[str, float] = {}
        evidence: List[str] = []
        keyword_hits: List[str] = []
        ai_analysis_text: Optional[str] = None

        # ── 1. 话术规则分析 ──────────────────────────────────────
        if text_result:
            scores["text_analysis"] = text_result.get("risk_score", 0)
            keyword_hits = text_result.get("keyword_hits", [])

            # 按类型收集权重
            for ftype, fscore in text_result.get("fraud_type_scores", {}).items():
                fraud_type_weights[ftype] = fraud_type_weights.get(ftype, 0) + fscore

            # 构建证据 —— 按诈骗类型分组展示命中关键词
            for ftype, kws in text_result.get("fraud_type_keywords", {}).items():
                evidence.append(f"【话术分析】检测到{ftype}关键词：{'、'.join(kws[:6])}")

            # 模式匹配证据
            for ind in text_result.get("risk_indicators", []):
                evidence.append(f"【模式匹配】{ind}")

        # ── 2. 企业核验 ──────────────────────────────────────────
        if company_result:
            scores["company_check"] = company_result.get("risk_score", 0)
            for ind in company_result.get("risk_indicators", []):
                evidence.append(f"【企业核验】{ind}")

        # ── 3. AI 语义分析 ───────────────────────────────────────
        if ai_result and ai_result.get("risk_score", 0) > 0:
            scores["ai_analysis"] = ai_result["risk_score"] * 100  # AI 返回 0-1

            ai_analysis_text = ai_result.get("reasoning", "")

            for ftype in ai_result.get("fraud_types", []):
                fraud_type_weights[ftype] = fraud_type_weights.get(ftype, 0) + 2.0

            for ev in ai_result.get("key_evidence", []):
                evidence.append(f"【AI 分析】{ev}")

        # ── 4. 加权计算最终分数 ──────────────────────────────────
        final_score = 0.0
        total_weight = 0.0
        for key, weight in cls.WEIGHTS.items():
            if key in scores:
                final_score += scores[key] * weight
                total_weight += weight

        if total_weight > 0:
            final_score = final_score / total_weight

        # ── 5. 风险等级 ──────────────────────────────────────────
        if final_score >= 70:
            level = "HIGH"
        elif final_score >= 40:
            level = "MEDIUM"
        elif final_score >= 15:
            level = "LOW"
        else:
            level = "SAFE"

        # ── 6. 诈骗类型排序 ──────────────────────────────────────
        fraud_types = [
            ft for ft, _ in sorted(
                fraud_type_weights.items(), key=lambda x: x[1], reverse=True
            )
        ]

        # ── 7. 置信度（基于数据源数量和丰富度） ──────────────────
        source_count = len(scores)
        confidence = min(
            0.3 + source_count * 0.2 + (0.1 if keyword_hits else 0),
            0.95,
        )

        # ── 8. 防范建议 ──────────────────────────────────────────
        suggestions: List[str] = []
        seen: set = set()

        # 企业核验的具体建议
        if company_result:
            for s in company_result.get("suggestions", []):
                if s not in seen:
                    suggestions.append(s)
                    seen.add(s)

        # 按诈骗类型添加建议
        for ft in fraud_types:
            for s in cls.SUGGESTIONS.get(ft, []):
                if s not in seen:
                    suggestions.append(s)
                    seen.add(s)

        # 通用建议
        for s in cls.SUGGESTIONS["_default"]:
            if s not in seen:
                suggestions.append(s)
                seen.add(s)

        # ── 9. 摘要 ──────────────────────────────────────────────
        parts = []
        if keyword_hits:
            parts.append(f"检测到 {len(keyword_hits)} 个风险关键词")
        if text_result and text_result.get("pattern_hits"):
            parts.append(f"{len(text_result['pattern_hits'])} 个风险模式")
        if fraud_types:
            parts.append(f"涉及{'、'.join(fraud_types[:3])}")
        if company_result and company_result.get("risk_indicators"):
            parts.append(f"企业存在 {len(company_result['risk_indicators'])} 项风险特征")

        if parts:
            summary = "，".join(parts)
        else:
            summary = "未检测到明显的招聘诈骗特征"

        if ai_analysis_text and len(ai_analysis_text) > 10:
            summary += f"。AI 研判：{ai_analysis_text[:80]}"

        return FraudRiskResult(
            risk_level=level,
            risk_score=round(final_score, 1),
            fraud_types=fraud_types,
            confidence=round(confidence, 2),
            summary=summary,
            evidence=evidence,
            suggestions=suggestions,
            keyword_hits=keyword_hits,
            ai_analysis=ai_analysis_text,
        )
