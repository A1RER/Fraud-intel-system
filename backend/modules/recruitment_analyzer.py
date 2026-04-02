# backend/modules/recruitment_analyzer.py
"""
模块：招聘话术智能分析
规则引擎（关键词匹配 + 正则模式识别）+ AI 语义分析
"""
import re
from typing import Dict, List
from loguru import logger


class RecruitmentAnalyzer:
    """招聘话术分析器 —— 识别招聘文本中的诈骗特征"""

    # ── 诈骗关键词库（类型 → 关键词 → 权重 0-1） ──────────────────
    FRAUD_KEYWORDS: Dict[str, Dict[str, float]] = {
        "付费培训诈骗": {
            "培训费": 1.0, "报名费": 1.0, "材料费": 0.9, "教材费": 0.9,
            "押金": 0.8, "预付款": 0.9, "保证金": 0.8, "手续费": 0.7,
            "服装费": 0.8, "体检费": 0.6, "建档费": 0.9, "入职费": 1.0,
            "包就业": 0.9, "包分配": 0.9, "包入职": 0.9, "保就业": 0.9,
            "先交钱": 1.0, "先缴费": 1.0, "交学费": 0.9,
        },
        "虚假内推诈骗": {
            "内推": 0.5, "内部推荐": 0.6, "内部渠道": 0.8,
            "保offer": 1.0, "付费内推": 1.0, "名额有限": 0.5,
            "内部名额": 0.8, "走后门": 0.7, "花钱买岗位": 1.0,
            "包进": 0.9, "直通名企": 0.7, "保录取": 1.0,
        },
        "高薪诱导诈骗": {
            "日赚": 0.9, "日入": 0.9, "轻松月入": 1.0,
            "月入过万": 0.7, "零基础高薪": 1.0, "高薪急聘": 0.6,
            "在家就能赚": 1.0, "躺赚": 1.0, "日结工资": 0.5,
            "兼职日结": 0.5, "轻松日赚": 1.0, "无门槛高薪": 1.0,
            "手机就能做": 0.8, "动动手指": 0.9,
        },
        "信息盗取诈骗": {
            "手持身份证": 1.0, "银行卡照片": 1.0,
            "提供验证码": 1.0, "实名认证费": 1.0,
            "身份证正反面": 0.9, "银行卡号": 0.7,
        },
    }

    # ── 正则模式库（捕捉结构化风险信号） ──────────────────────────
    RISK_PATTERNS = [
        {
            "name": "收费金额",
            "regex": re.compile(
                r"(?:缴纳|交|付|收取|支付|转账|汇款)\s*(\d[\d,.]*)\s*(?:元|块|RMB|¥)"
            ),
            "fraud_type": "付费培训诈骗",
            "weight": 0.9,
        },
        {
            "name": "私聊引导",
            "regex": re.compile(
                r"(?:加|添加|扫码|私聊|详聊)\s*(?:微信|QQ|qq|V信|v信|wx|WX|企微|电话|手机)"
            ),
            "fraud_type": None,
            "weight": 0.4,
        },
        {
            "name": "紧迫催促",
            "regex": re.compile(
                r"(?:仅剩|限时|最后|赶紧|抓紧|名额不多|先到先得|今天截止|急急急|速度)"
            ),
            "fraud_type": None,
            "weight": 0.4,
        },
        {
            "name": "高薪数字",
            "regex": re.compile(
                r"(?:月薪|月入|日入|日赚|时薪|周薪|底薪)\s*(\d[\d,.]*)\s*(?:\+|以上|起)?"
            ),
            "fraud_type": "高薪诱导诈骗",
            "weight": 0.3,
        },
        {
            "name": "担保承诺",
            "regex": re.compile(
                r"(?:保证|承诺|确保|包)\s*(?:入职|录用|就业|通过|上岸|拿到offer)"
            ),
            "fraud_type": "虚假内推诈骗",
            "weight": 0.7,
        },
    ]

    # ── AI 分析 Prompt ───────────────────────────────────────────
    _AI_PROMPT = """你是一个专业的招聘诈骗识别引擎。请分析以下文本是否包含招聘诈骗特征。

重点关注以下诈骗类型：
1. 付费培训诈骗：以培训费、材料费、押金等名义在入职前收费
2. 虚假内推诈骗：以内部推荐、保offer为名收取费用
3. 高薪诱导诈骗：以不合理高薪吸引受害者参与刷单、赌博等
4. 信息盗取诈骗：以入职为名骗取身份证、银行卡等敏感信息
5. 虚假招聘诈骗：以不存在的岗位骗取个人信息或钱财

请严格按以下 JSON 格式输出，不要输出任何其他内容：
{
  "risk_score": 0.0到1.0的浮点数,
  "fraud_types": ["识别到的诈骗类型"],
  "key_evidence": ["逐条列出关键证据，格式：【证据类型】原文引用 → 风险说明"],
  "risk_indicators": ["具体风险指标"],
  "reasoning": "综合分析说明（100字以上），包含：诈骗模式判断、核心风险点、对求职者的具体风险"
}"""

    # ── 公开方法 ─────────────────────────────────────────────────

    @classmethod
    def analyze(cls, text: str, extra_keywords: List[str] = None) -> dict:
        """
        规则引擎分析招聘文本

        返回:
            keyword_hits:        命中的关键词列表 [str]
            fraud_type_keywords: 按诈骗类型分组 {type: [keywords]}
            pattern_hits:        正则命中 [{name, match}]
            risk_indicators:     风险指标描述 [str]
            fraud_type_scores:   各类型累计权重 {type: float}
            risk_score:          风险分 0-100
        """
        if not text or not text.strip():
            return cls._empty()

        keyword_hits: List[str] = []
        fraud_type_keywords: Dict[str, List[str]] = {}
        type_scores: Dict[str, float] = {}

        # 1. 关键词扫描
        for ftype, kw_dict in cls.FRAUD_KEYWORDS.items():
            for kw, weight in kw_dict.items():
                if kw in text:
                    keyword_hits.append(kw)
                    fraud_type_keywords.setdefault(ftype, []).append(kw)
                    type_scores[ftype] = type_scores.get(ftype, 0) + weight

        # 用户自定义关键词
        if extra_keywords:
            for kw in extra_keywords:
                if kw in text and kw not in keyword_hits:
                    keyword_hits.append(kw)

        # 2. 正则模式扫描
        pattern_hits = []
        risk_indicators = []
        for p in cls.RISK_PATTERNS:
            matches = p["regex"].findall(text)
            if matches:
                sample = matches[0] if isinstance(matches[0], str) else str(matches[0])
                pattern_hits.append({"name": p["name"], "match": sample})
                risk_indicators.append(f"{p['name']}：检测到「{sample}」")
                if p["fraud_type"]:
                    type_scores[p["fraud_type"]] = (
                        type_scores.get(p["fraud_type"], 0) + p["weight"]
                    )

        # 3. 风险评分
        total_weight = sum(type_scores.values())
        risk_score = min(total_weight * 12, 100)
        if len(type_scores) > 1:
            risk_score = min(risk_score + 15, 100)

        return {
            "keyword_hits": keyword_hits,
            "fraud_type_keywords": fraud_type_keywords,
            "pattern_hits": pattern_hits,
            "risk_indicators": risk_indicators,
            "fraud_type_scores": type_scores,
            "risk_score": round(risk_score, 1),
        }

    @classmethod
    def ai_analyze(cls, text: str, engine: str = "auto") -> dict:
        """
        AI 语义分析（调用 DeepSeek）

        返回:
            risk_score:      0-1
            fraud_types:     [str]
            key_evidence:    [str]
            risk_indicators: [str]
            reasoning:       str
        """
        from backend.modules.ai_analyzer import _call_llm, _parse_json

        if not text or len(text.strip()) < 10:
            return {
                "risk_score": 0.0, "fraud_types": [], "key_evidence": [],
                "risk_indicators": [], "reasoning": "输入文本过短，无法进行 AI 分析",
            }

        prompt = f"{cls._AI_PROMPT}\n\n请分析以下文本：\n\n{text[:8000]}"
        try:
            raw, provider = _call_llm(prompt, max_tokens=4096, engine=engine)
            result = _parse_json(raw)
            result["risk_score"] = max(0.0, min(1.0, float(result.get("risk_score", 0.0))))
            result["_provider"] = provider
            logger.info(
                f"[RecruitmentAnalyzer] AI 分析完成 [{provider}]: "
                f"score={result['risk_score']:.2f}"
            )
            return result
        except Exception as e:
            logger.error(f"[RecruitmentAnalyzer] AI 分析失败: {e}")
            return {
                "risk_score": 0.0, "fraud_types": [], "key_evidence": [],
                "risk_indicators": [], "reasoning": f"AI 分析失败：{e}",
            }

    @classmethod
    def _empty(cls) -> dict:
        return {
            "keyword_hits": [], "fraud_type_keywords": {},
            "pattern_hits": [], "risk_indicators": [],
            "fraud_type_scores": {}, "risk_score": 0.0,
        }
