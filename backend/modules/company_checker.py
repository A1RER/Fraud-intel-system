# backend/modules/company_checker.py
"""
模块：企业信息核验
通过企业名称进行基础风险评估（名称模式分析 + AI 辅助研判）
"""
import re
from typing import List, Tuple
from loguru import logger


class CompanyChecker:
    """企业信息核验器 —— 基于名称特征和行业属性进行风险评估"""

    # ── 高风险行业关键词（招聘场景下） ────────────────────────────
    HIGH_RISK_INDUSTRIES: List[Tuple[str, float, str]] = [
        ("人力资源",   0.4, "人力资源行业（劳务派遣诈骗高发）"),
        ("劳务派遣",   0.5, "劳务派遣行业（常被用于虚假招聘）"),
        ("劳务服务",   0.4, "劳务服务行业（招聘诈骗高发）"),
        ("教育培训",   0.4, "教育培训行业（付费培训诈骗高发）"),
        ("教育咨询",   0.4, "教育咨询行业（付费培训诈骗高发）"),
        ("职业培训",   0.5, "职业培训行业（付费培训诈骗高发）"),
        ("信息咨询",   0.3, "信息咨询行业（虚假中介高发）"),
        ("商务咨询",   0.3, "商务咨询行业（经营范围模糊）"),
        ("网络科技",   0.2, "网络科技行业（需核实具体业务）"),
        ("文化传媒",   0.2, "文化传媒行业（需核实具体业务）"),
        ("电子商务",   0.2, "电子商务行业（刷单诈骗高发）"),
    ]

    # ── 可疑名称模式 ─────────────────────────────────────────────
    SUSPICIOUS_PATTERNS: List[Tuple[str, float, str]] = [
        (r"工作室$",               0.4, "非正规公司主体（工作室）"),
        (r"服务部$",               0.4, "非正规公司主体（服务部）"),
        (r"经营部$",               0.4, "非正规公司主体（经营部）"),
        (r"(?:总部|集团|控股|国际)", 0.3, "使用夸大性名称（集团/国际/控股）"),
        (r"^.{2,4}公司$",          0.2, "公司名称过短，可能不真实"),
    ]

    @classmethod
    async def check(cls, company_name: str, context: str = "") -> dict:
        """
        核验企业信息

        返回:
            company_name:    str
            risk_score:      float (0-100)
            risk_indicators: [str]
            suggestions:     [str]
        """
        if not company_name or not company_name.strip():
            return cls._empty("")

        name = company_name.strip()
        risk_score = 0.0
        indicators: List[str] = []

        # 1. 名称模式分析
        for pattern, weight, desc in cls.SUSPICIOUS_PATTERNS:
            if re.search(pattern, name):
                risk_score += weight * 25
                indicators.append(desc)

        # 2. 行业关键词分析
        for industry, weight, desc in cls.HIGH_RISK_INDUSTRIES:
            if industry in name:
                risk_score += weight * 20
                indicators.append(desc)

        # 3. 名称长度
        if len(name) < 4:
            risk_score += 10
            indicators.append("公司名称过短，信息不足以判断")

        # 名称分析单独不应封顶，留空间给 AI 提升
        risk_score = min(risk_score, 80)

        # 4. 建议
        suggestions = [
            '建议在「国家企业信用信息公示系统」(gsxt.gov.cn)查询企业注册信息',
            '建议在「天眼查」或「企查查」查看企业成立时间、注册资本和经营状态',
        ]
        if indicators:
            suggestions.append('建议在「黑猫投诉」等平台搜索该企业是否存在投诉记录')

        return {
            "company_name": name,
            "risk_score": round(risk_score, 1),
            "risk_indicators": indicators,
            "suggestions": suggestions,
        }

    @classmethod
    def ai_check(cls, company_name: str, context: str = "", engine: str = "auto") -> dict:
        """
        AI 辅助企业风险分析

        返回:
            risk_score:      0-1
            risk_indicators: [str]
            reasoning:       str
            suggestions:     [str]
        """
        from backend.modules.gemini_analyzer import _call_llm, _parse_json

        prompt = f"""你是一名反诈专家。请分析以下企业在招聘场景中的可疑程度。

企业名称：{company_name}
{f'相关背景信息：{context[:2000]}' if context else ''}

请严格按以下 JSON 格式输出，不要输出任何其他内容：
{{
  "risk_score": 0.0到1.0的浮点数,
  "risk_indicators": ["逐条列出风险指标"],
  "reasoning": "综合分析说明（50字以上）",
  "suggestions": ["核验建议"]
}}"""

        try:
            raw, provider = _call_llm(prompt, max_tokens=2048, engine=engine)
            result = _parse_json(raw)
            result["risk_score"] = max(0.0, min(1.0, float(result.get("risk_score", 0.0))))
            result["_provider"] = provider
            logger.info(
                f"[CompanyChecker] AI 分析完成 [{provider}]: "
                f"score={result['risk_score']:.2f}"
            )
            return result
        except Exception as e:
            logger.error(f"[CompanyChecker] AI 分析失败: {e}")
            return {
                "risk_score": 0.0, "risk_indicators": [],
                "reasoning": f"AI 分析失败：{e}", "suggestions": [],
            }

    @classmethod
    def _empty(cls, name: str) -> dict:
        return {
            "company_name": name,
            "risk_score": 0.0,
            "risk_indicators": [],
            "suggestions": [],
        }
