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


# ── 统一文本生成（支持用户选择引擎）──────────────────────────
def _call_llm(prompt: str, max_tokens: int = 1024, temperature: float = 0.1,
              engine: str = "auto") -> tuple:
    """
    返回 (response_text, provider_name)
    engine: "auto" = Gemini优先DeepSeek备选, "gemini" = 仅Gemini, "deepseek" = 仅DeepSeek
    """
    try_gemini = engine in ("auto", "gemini")
    try_deepseek = engine in ("auto", "deepseek")

    # 尝试 Gemini
    if try_gemini and GEMINI_AVAILABLE and _gemini_key():
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
            if engine == "gemini":
                raise RuntimeError(f"Gemini 调用失败: {e}")
            logger.warning(f"[AI] Gemini 调用失败，切换 DeepSeek: {e}")

    # DeepSeek
    if try_deepseek and DEEPSEEK_AVAILABLE and _deepseek_key():
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
            logger.error(f"[AI] DeepSeek 调用失败: {e}")

    raise RuntimeError(f"所选 AI 引擎不可用 (engine={engine})")


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

    SYSTEM_PROMPT = """你是一个专业的网络欺诈检测引擎。给定一个网站的页面文本，你需要深度分析其是否包含欺诈/诈骗内容。

请严格按以下 JSON 格式输出，不要输出任何其他内容：
{
  "risk_score": 0.0到1.0的浮点数，表示欺诈风险程度,
  "fraud_types": ["检测到的所有欺诈类型，如：投资诈骗、赌博诈骗、钓鱼网站、刷单诈骗、冒充公检法、杀猪盘、虚假购物、情感诈骗等"],
  "key_evidence": ["从文本中逐条提取的关键证据，每条格式为：【证据类型】原文引用 → 风险说明，至少5条，越多越好"],
  "risk_indicators": ["具体风险指标列表，说明每个指标的具体表现和危险程度，至少列出5项"],
  "reasoning": "详细的综合判断说明，需包含：1）整体欺诈模式判断；2）最关键的3个风险点；3）与正常网站的差异分析；4）受骗人群画像预测（100字以上）"
}

评分标准：
- 0.0~0.2: 正常合法网站，内容可信
- 0.2~0.4: 存在轻微可疑内容，需关注
- 0.4~0.6: 中度可疑，有明显诱导性话术
- 0.6~0.8: 高度可疑，多项欺诈特征并存
- 0.8~1.0: 几乎确定是欺诈网站，证据充分"""

    @classmethod
    def analyze(cls, page_text: str, page_title: str = "", engine: str = "auto") -> Dict:
        if not page_text:
            return {"risk_score": 0.0, "fraud_types": [], "key_evidence": [],
                    "reasoning": "未采集到页面文本，跳过内容分析", "_provider": ""}

        text_input = page_text[:8000]
        if page_title:
            text_input = f"[网站标题] {page_title}\n\n[页面正文]\n{text_input}"

        try:
            raw, provider = _call_llm(
                f"{cls.SYSTEM_PROMPT}\n\n请分析以下网站文本：\n\n{text_input}",
                max_tokens=2048, engine=engine,
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

    VISION_PROMPT = """你是一个专业的网站视觉欺诈检测引擎。请深度分析这张网站截图，判断它是否可能是欺诈/钓鱼网站。

重点检查以下视觉维度：
1. 品牌仿冒：是否仿冒银行、支付宝、微信、政府、知名电商等机构的 Logo/配色/UI布局
2. 博彩赌博：是否包含筹码、老虎机、开奖动效、赔率展示等视觉元素
3. 虚假投资：是否有K线图、收益曲线、VIP等级、充值按钮、"日收益XX%"等元素
4. 制作质量：图片是否模糊/拼贴/水印未去除、排版是否混乱、字体是否统一
5. 心理操控：是否有倒计时、红色警告框、"仅剩X名额"、弹窗遮挡等紧迫感设计
6. 信任构建：是否有伪造的监管机构图标、虚假荣誉证书、刷量的用户评价截图

请严格按以下 JSON 格式输出，不要输出任何其他内容：
{
  "visual_risk_score": 0.0到1.0的浮点数,
  "is_phishing": true或false,
  "impersonates": "仿冒的目标机构名称（如：工商银行、支付宝），无仿冒则为null",
  "visual_features": ["每条详细描述一个可疑视觉特征及其风险含义，至少列出所有发现的特征"],
  "description": "对截图的完整视觉分析，包含：页面整体布局描述、核心风险视觉元素、制作质量评估、与合法网站的对比差异（100字以上）"
}"""

    @classmethod
    def analyze(cls, screenshot_b64: str, engine: str = "auto") -> Dict:
        default = {"visual_risk_score": 0.0, "is_phishing": False, "impersonates": None,
                    "visual_features": [], "description": "AI 视觉分析未执行"}

        # 视觉分析仅 Gemini 支持；用户选择仅 DeepSeek 时跳过
        if engine == "deepseek":
            default["description"] = "DeepSeek 不支持视觉分析，已跳过"
            return default

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
                    temperature=0.2,
                    max_output_tokens=2048,
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

    REPORT_PROMPT = """你是一名资深网络犯罪侦查分析师，拥有10年以上网络诈骗案件侦办经验。根据以下情报数据，撰写一份详尽专业的涉诈网站侦查分析报告。

写作要求：
1. 使用专业、严谨的警务文书风格，语言精准有力
2. 每个章节必须有充实内容，不得敷衍带过，每节至少200字
3. 基于给定数据深度推理，结合诈骗犯罪规律进行专业研判
4. 关键数据必须在报告中具体引用（IP、域名、评分等）
5. 侦查建议必须具体可操作，区分紧急/中期/长期行动

请按以下结构输出（使用 markdown 格式，内容必须详尽）：

## 一、目标概况
全面描述被分析网站的基本信息，包括：网址、域名注册情况、托管位置、网站类型判断、
表面伪装手法（以何种合法业务为幌子）、潜在受害群体分析。

## 二、风险评估结论
给出明确的综合研判结论，包括：WRAS评分解读、风险等级含义、置信度分析、
与同类诈骗网站的对比、研判人员建议采取的行动级别。

## 三、关键发现（不少于5条）
逐条列出最重要的发现，格式为：
**发现N：[标题]**
事实描述：……
风险含义：……
证据强度：高/中/低

## 四、技术基础设施分析
深度分析域名/SSL/服务器/网络层面：
- 域名注册策略（注册时间、隐匿手法）
- SSL证书情况及异常点
- 服务器地理位置与托管商分析（境外服务器的具体风险）
- CDN/跳转链路的反侦查意图分析
- IP地址归属及同一IP关联网站风险

## 五、内容与舆情综合分析
分析页面话术、视觉欺骗和社会舆情：
- 欺诈话术特征（具体诱导性词汇和句式分析）
- 视觉仿冒与心理操控手法
- 受害人投诉情况分析（投诉量、投诉内容模式）
- 搜索引擎舆情分析
- AI内容检测结果解读

## 六、犯罪团伙画像（情报研判）
基于现有证据推断：
- 组织架构猜测（单干/团伙）
- 技术能力评估
- 运营模式分析
- 可能的上下游关联

## 七、侦查建议与处置预案
**立即行动（24小时内）：**
- …

**中期侦查（1-2周）：**
- …

**长期跟踪（持续监控）：**
- …

**证据固定要点：**
- …"""

    @classmethod
    def generate(cls, context: Dict, engine: str = "auto") -> tuple:
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
                max_tokens=4096, temperature=0.4, engine=engine,
            )
            logger.info(f"[AI] 侦查报告生成完成 [{provider}]")
            return report_text, provider
        except Exception as e:
            logger.error(f"[AI] 报告生成失败: {e}")
            return f"⚠️ AI 报告生成失败：{e}", ""
