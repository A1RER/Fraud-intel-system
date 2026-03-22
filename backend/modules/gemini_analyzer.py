# backend/modules/gemini_analyzer.py
"""
模块五：AI 智能分析
支持双引擎：Gemini（主） + DeepSeek（备选）
- Gemini 限流 / 不可用时自动切换 DeepSeek
- 视觉分析仅 Gemini 支持
"""
import os
import json
import base64
from typing import Dict
from loguru import logger

from config.settings import GEMINI_MODEL, DEEPSEEK_MODEL, DEEPSEEK_BASE_URL

# ── SDK 可用性检测 ────────────────────────────────────────────
try:
    from google import genai
    from google.genai import types as gemini_types
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

try:
    from openai import OpenAI
    DEEPSEEK_AVAILABLE = True
except ImportError:
    DEEPSEEK_AVAILABLE = False


# ── 客户端工厂 ────────────────────────────────────────────────
def _gemini_key():
    return os.getenv("GEMINI_API_KEY", "")

def _deepseek_key():
    return os.getenv("DEEPSEEK_API_KEY", "")

def _get_gemini():
    return genai.Client(api_key=_gemini_key())

def _get_deepseek():
    return OpenAI(api_key=_deepseek_key(), base_url=DEEPSEEK_BASE_URL)


# ── 统一文本生成（Gemini 优先，DeepSeek 备选）─────────────────
def _call_llm(prompt: str, max_tokens: int = 1024, temperature: float = 0.1) -> tuple:
    """
    返回 (response_text, provider_name)
    优先 Gemini，失败则 DeepSeek
    """
    # 尝试 Gemini
    if GEMINI_AVAILABLE and _gemini_key():
        try:
            client = _get_gemini()
            resp = client.models.generate_content(
                model=GEMINI_MODEL,
                contents=prompt,
                config=gemini_types.GenerateContentConfig(
                    temperature=temperature,
                    max_output_tokens=max_tokens,
                ),
            )
            text = resp.text
            if text:
                return text.strip(), f"Gemini ({GEMINI_MODEL})"
        except Exception as e:
            logger.warning(f"[AI] Gemini 调用失败，切换 DeepSeek: {e}")

    # 备选 DeepSeek
    if DEEPSEEK_AVAILABLE and _deepseek_key():
        try:
            client = _get_deepseek()
            resp = client.chat.completions.create(
                model=DEEPSEEK_MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=temperature,
                max_tokens=max_tokens,
            )
            text = resp.choices[0].message.content
            if text:
                return text.strip(), f"DeepSeek ({DEEPSEEK_MODEL})"
        except Exception as e:
            logger.error(f"[AI] DeepSeek 调用也失败: {e}")

    raise RuntimeError("Gemini 和 DeepSeek 均不可用")


def _parse_json(raw: str) -> dict:
    """从 LLM 回复中提取 JSON"""
    if "```json" in raw:
        raw = raw.split("```json")[1].split("```")[0].strip()
    elif "```" in raw:
        raw = raw.split("```")[1].split("```")[0].strip()
    return json.loads(raw)


# ── 内容语义分析 ──────────────────────────────────────────────
class GeminiContentAnalyzer:
    """页面文本语义级欺诈检测（双引擎）"""

    SYSTEM_PROMPT = """你是一个专业的网络欺诈检测引擎。给定一个网站的页面文本，你需要分析其是否包含欺诈/诈骗内容。

请严格按以下 JSON 格式输出，不要输出任何其他内容：
{
  "risk_score": 0.0到1.0的浮点数，表示欺诈风险程度,
  "fraud_types": ["检测到的欺诈类型列表，如：投资诈骗、赌博诈骗、钓鱼网站、刷单诈骗、冒充公检法等"],
  "key_evidence": ["从文本中提取的关键证据句子，最多5条"],
  "reasoning": "一句话说明判断理由"
}

评分标准：
- 0.0~0.2: 正常合法网站
- 0.2~0.4: 存在轻微可疑内容
- 0.4~0.6: 中度可疑，有明显诱导性话术
- 0.6~0.8: 高度可疑，多项欺诈特征
- 0.8~1.0: 几乎确定是欺诈网站"""

    @classmethod
    def analyze(cls, page_text: str, page_title: str = "") -> Dict:
        if not page_text:
            return {"risk_score": 0.0, "fraud_types": [], "key_evidence": [],
                    "reasoning": "未采集到页面文本，跳过内容分析", "_provider": ""}

        text_input = page_text[:8000]
        if page_title:
            text_input = f"[网站标题] {page_title}\n\n[页面正文]\n{text_input}"

        try:
            raw, provider = _call_llm(
                f"{cls.SYSTEM_PROMPT}\n\n请分析以下网站文本：\n\n{text_input}"
            )
            result = _parse_json(raw)
            result["risk_score"] = max(0.0, min(1.0, float(result.get("risk_score", 0.0))))
            result["_provider"] = provider
            logger.info(f"[AI] 内容分析完成 [{provider}]: risk_score={result['risk_score']:.2f}")
            return result
        except Exception as e:
            logger.error(f"[AI] 内容分析失败: {e}")
            return {"risk_score": 0.0, "fraud_types": [], "key_evidence": [],
                    "reasoning": f"AI 分析失败：{e}", "_provider": ""}


# ── 视觉分析（仅 Gemini，DeepSeek 不支持）────────────────────
class GeminiVisionAnalyzer:
    """网站截图视觉欺诈检测（仅 Gemini）"""

    VISION_PROMPT = """你是一个专业的网站视觉欺诈检测引擎。请分析这张网站截图，判断它是否可能是欺诈/钓鱼网站。

关注以下视觉特征：
1. 是否仿冒知名机构（银行、支付宝、微信、政府网站等）的 UI 风格
2. 是否包含赌博、博彩相关的视觉元素（筹码、老虎机、开奖等）
3. 是否有虚假投资平台特征（K线图、收益曲线、充值入口等）
4. 页面设计是否粗糙、不专业（低质量素材、排版混乱等）
5. 是否有诱导性弹窗、倒计时、"限时优惠"等视觉陷阱

请严格按以下 JSON 格式输出，不要输出任何其他内容：
{
  "visual_risk_score": 0.0到1.0的浮点数,
  "is_phishing": true或false,
  "impersonates": "仿冒的目标机构名称，如果没有则为null",
  "visual_features": ["检测到的可疑视觉特征列表"],
  "description": "一句话描述截图内容和判断"
}"""

    @classmethod
    def analyze(cls, screenshot_b64: str) -> Dict:
        default = {"visual_risk_score": 0.0, "is_phishing": False, "impersonates": None,
                    "visual_features": [], "description": "AI 视觉分析未执行"}

        if not screenshot_b64 or not GEMINI_AVAILABLE or not _gemini_key():
            return default

        try:
            client = _get_gemini()
            image_bytes = base64.b64decode(screenshot_b64)
            image_part = gemini_types.Part.from_bytes(data=image_bytes, mime_type="image/png")

            resp = client.models.generate_content(
                model=GEMINI_MODEL,
                contents=[cls.VISION_PROMPT, image_part],
                config=gemini_types.GenerateContentConfig(
                    temperature=0.1,
                    max_output_tokens=1024,
                ),
            )
            raw = resp.text.strip()
            result = _parse_json(raw)
            result["visual_risk_score"] = max(0.0, min(1.0, float(result.get("visual_risk_score", 0.0))))
            logger.info(f"[AI] 视觉分析完成: risk={result['visual_risk_score']:.2f}")
            return result
        except Exception as e:
            logger.error(f"[AI] 视觉分析失败: {e}")
            return default


# ── AI 侦查报告生成（双引擎）─────────────────────────────────
class GeminiReportGenerator:
    """AI 侦查报告（双引擎）"""

    REPORT_PROMPT = """你是一名资深网络犯罪侦查分析师。根据以下情报数据，撰写一份专业的涉诈网站侦查分析报告。

要求：
1. 使用专业、严谨的警务文书风格
2. 结构清晰，结论明确
3. 基于证据进行推理，不要臆断
4. 给出具体的下一步侦查建议

请按以下结构输出（纯文本，使用 markdown 格式）：

## 一、目标概况
简要描述被分析网站的基本信息

## 二、风险评估结论
综合风险等级、评分和核心判断

## 三、关键发现
列出最重要的 3-5 条发现，每条说明事实 + 风险含义

## 四、技术分析
域名/SSL/服务器等技术层面的分析

## 五、内容分析
页面话术/视觉/舆情等内容层面的分析

## 六、侦查建议
针对当前风险等级给出具体的下一步行动建议"""

    @classmethod
    def generate(cls, context: Dict) -> tuple:
        """返回 (report_text, provider_name)"""
        intel_summary = f"""
【目标网址】{context.get('url', '未知')}
【域名】{context.get('domain', '未知')}
【WRAS 风险评分】{context.get('wras_score', 0):.1f} / 100
【风险等级】{context.get('risk_level', '未知')}
【置信度】{context.get('confidence', 0):.0%}

【域名注册天数】{context.get('domain_age_days', '未知')} 天
【ICP 备案】{context.get('icp_record', '无')}
【WHOIS 隐私保护】{'是' if context.get('whois_privacy') else '否'}
【SSL 证书】{'有效' if context.get('ssl_valid') else '无效'} | 自签名：{'是' if context.get('ssl_self_signed') else '否'}
【服务器 IP】{context.get('server_ip', '未知')}
【服务器国家】{context.get('server_country', '未知')}
【ISP】{context.get('server_isp', '未知')}
【CDN】{'是' if context.get('is_cdn') else '否'}
【跳转次数】{context.get('redirect_count', 0)}
【黑名单命中】{'是' if context.get('blacklist_hit') else '否'}
【投诉量】{context.get('complaint_count', 0)} 条

【AI 内容分析】欺诈风险 {context.get('ai_content_score', 0):.0%}
【AI 检测到的欺诈类型】{', '.join(context.get('ai_fraud_types', [])) or '无'}
【AI 关键证据】{'; '.join(context.get('ai_evidence', [])) or '无'}

【舆情摘要】{'; '.join(context.get('search_snippets', [])) or '无'}

【各维度得分】
{chr(10).join(f'  - {k}: {v:.1f}' for k, v in context.get('score_breakdown', {}).items())}

【主要风险因子贡献】
{chr(10).join(f'  - {k}: {v:.2f}分' for k, v in sorted(context.get('feature_contrib', {}).items(), key=lambda x: x[1], reverse=True)[:6])}
"""
        try:
            report_text, provider = _call_llm(
                f"{cls.REPORT_PROMPT}\n\n以下是本次分析的情报数据：\n{intel_summary}",
                max_tokens=2048, temperature=0.3,
            )
            logger.info(f"[AI] 侦查报告生成完成 [{provider}]")
            return report_text, provider
        except Exception as e:
            logger.error(f"[AI] 报告生成失败: {e}")
            return f"⚠️ AI 报告生成失败：{e}", ""
