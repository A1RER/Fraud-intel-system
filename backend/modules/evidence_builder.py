# backend/modules/evidence_builder.py
"""
证据链生成器 —— 将多源分析结果组装为结构化、可展示的证据链
"""
from datetime import datetime
from typing import Dict, List, Optional


class EvidenceBuilder:
    """将分散的分析结果组装为完整证据链"""

    # 证据强度映射
    STRENGTH_MAP = {
        "keyword":  "中",
        "pattern":  "中",
        "company":  "低",
        "ai":       "高",
        "url":      "高",
    }

    @classmethod
    def build(
        cls,
        report_id: str,
        input_type: str,
        text_result: Optional[dict] = None,
        company_result: Optional[dict] = None,
        ai_result: Optional[dict] = None,
        risk_level: str = "SAFE",
        risk_score: float = 0.0,
    ) -> Dict:
        """
        构建结构化证据链

        返回:
            report_id:     str
            generated_at:  str
            risk_level:    str
            risk_score:    float
            evidence_chain: [
                {
                    source:    str,   # 来源模块
                    category:  str,   # 证据类别
                    content:   str,   # 证据内容
                    strength:  str,   # 证据强度：高/中/低
                }
            ]
            conclusion:    str   # 综合结论
        """
        chain: List[Dict] = []

        # ── 话术分析证据 ─────────────────────────────────────────
        if text_result:
            # 关键词命中
            for ftype, kws in text_result.get("fraud_type_keywords", {}).items():
                chain.append({
                    "source": "话术规则引擎",
                    "category": f"{ftype} - 关键词命中",
                    "content": f"检测到以下风险关键词：{'、'.join(kws[:8])}",
                    "strength": cls.STRENGTH_MAP["keyword"],
                })

            # 模式匹配
            for hit in text_result.get("pattern_hits", []):
                chain.append({
                    "source": "模式匹配引擎",
                    "category": hit["name"],
                    "content": f"匹配到风险模式：{hit['match']}",
                    "strength": cls.STRENGTH_MAP["pattern"],
                })

        # ── 企业核验证据 ─────────────────────────────────────────
        if company_result:
            for ind in company_result.get("risk_indicators", []):
                chain.append({
                    "source": "企业信息核验",
                    "category": "企业风险特征",
                    "content": ind,
                    "strength": cls.STRENGTH_MAP["company"],
                })

        # ── AI 分析证据 ──────────────────────────────────────────
        if ai_result and ai_result.get("risk_score", 0) > 0:
            for ev in ai_result.get("key_evidence", []):
                chain.append({
                    "source": "AI 语义分析",
                    "category": "AI 识别证据",
                    "content": ev,
                    "strength": cls.STRENGTH_MAP["ai"],
                })
            for ri in ai_result.get("risk_indicators", []):
                chain.append({
                    "source": "AI 语义分析",
                    "category": "AI 风险指标",
                    "content": ri,
                    "strength": cls.STRENGTH_MAP["ai"],
                })

        # ── 综合结论 ─────────────────────────────────────────────
        if not chain:
            conclusion = "未发现明显诈骗证据，建议通过正规渠道进一步核实。"
        else:
            high_count = sum(1 for e in chain if e["strength"] == "高")
            mid_count = sum(1 for e in chain if e["strength"] == "中")
            sources = list({e["source"] for e in chain})
            conclusion = (
                f"共采集到 {len(chain)} 条证据（"
                f"高强度 {high_count} 条、中强度 {mid_count} 条），"
                f"来源于{len(sources)}个分析模块（{'、'.join(sources)}）。"
                f"综合风险评分 {risk_score:.1f}，风险等级 {risk_level}。"
            )

        return {
            "report_id": report_id,
            "generated_at": datetime.utcnow().isoformat(),
            "risk_level": risk_level,
            "risk_score": risk_score,
            "evidence_chain": chain,
            "conclusion": conclusion,
        }
