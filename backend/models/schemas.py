# backend/models/schemas.py
"""
数据模型定义 —— 情报流各阶段的结构化载体
"""
import re
from pydantic import BaseModel, HttpUrl, Field, field_validator
from typing import Optional, Dict, List, Any
from datetime import datetime
from enum import Enum

# 合法 URL 正则：支持 http(s):// 前缀或直接输入域名
_URL_RE = re.compile(
    r"^(https?://)?"                      # 可选协议
    r"([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"  # 域名
    r"[a-zA-Z]{2,63}"                     # 顶级域名
    r"(:\d{1,5})?"                         # 可选端口
    r"(/\S*)?$"                            # 可选路径
)


class RiskLevelEnum(str, Enum):
    RED    = "RED"
    ORANGE = "ORANGE"
    YELLOW = "YELLOW"
    GREEN  = "GREEN"


# ─── 阶段一：采集原始情报 ─────────────────────────────────────
class RawIntelligence(BaseModel):
    """OSINT 原始采集结果"""
    url:              str
    collected_at:     datetime = Field(default_factory=datetime.utcnow)

    # 域名/注册信息
    domain:           str
    domain_age_days:  Optional[int]   = None
    registrar:        Optional[str]   = None
    whois_privacy:    bool            = False
    icp_record:       Optional[str]   = None    # None = 未备案

    # SSL 信息
    ssl_valid:        bool            = False
    ssl_issuer:       Optional[str]   = None
    ssl_self_signed:  bool            = False
    ssl_expiry_days:  Optional[int]   = None

    # 服务器信息
    server_ip:        Optional[str]   = None
    server_country:   Optional[str]   = None
    server_isp:       Optional[str]   = None
    is_cdn:           bool            = False

    # 页面内容
    page_title:       Optional[str]   = None
    page_text:        Optional[str]   = None
    page_html:        Optional[str]   = None
    screenshot_b64:   Optional[str]   = None    # base64 截图

    # 页面技术特征
    resource_errors:  int             = 0
    total_resources:  int             = 0
    redirect_chain:   List[str]       = []

    # 外部舆情
    search_snippets:  List[str]       = []      # 搜索引擎摘要
    social_mentions:  List[str]       = []      # 微博/知乎 舆情
    complaint_count:  int             = 0       # 投诉平台计数
    blacklist_hit:    bool            = False


# ─── 阶段二：特征工程输出 ─────────────────────────────────────
class FeatureVector(BaseModel):
    """标准化特征向量（值域 0~1，越高风险越大）"""
    domain_age_days:         float = 0.0   # 反向归一化
    icp_missing:             float = 0.0
    whois_privacy_protected: float = 0.0
    ssl_self_signed:         float = 0.0
    ip_overseas:             float = 0.0
    ip_cdn_abuse:            float = 0.0
    keyword_risk_score:      float = 0.0
    phishing_visual_sim:     float = 0.0
    resource_load_anomaly:   float = 0.0
    public_sentiment_neg:    float = 0.0
    complaint_count_norm:    float = 0.0
    blacklist_hit:           float = 0.0

    # 可解释性附加信息
    keyword_hits:            Dict[str, List[str]] = {}   # 命中词
    sentiment_detail:        Optional[str]        = None


# ─── 阶段三：WRAS 评分结果 ─────────────────────────────────────
class WRASResult(BaseModel):
    """加权风险评分（Weighted Risk Assessment Score）"""
    raw_score:          float                    # 加权总分（0~100）
    confidence_coeff:   float                    # 置信度系数
    final_score:        float                    # 最终分 = raw_score * confidence_coeff
    risk_level:         RiskLevelEnum
    feature_contrib:    Dict[str, float]         # 各特征贡献热力图数据
    score_breakdown:    Dict[str, float]         # 分维度得分


# ─── 阶段四：决策支持输出 ─────────────────────────────────────
class DisposalPlan(BaseModel):
    """警务处置预案"""
    level:   str
    action:  str
    urgency: str
    steps:   List[str]


class GeminiAnalysis(BaseModel):
    """Gemini AI 分析结果"""
    # 元信息（用于验证来源）
    model_name:          str = ""
    ai_elapsed_s:        float = 0.0
    # 内容语义分析
    content_risk_score:  float = 0.0
    fraud_types:         List[str] = []
    key_evidence:        List[str] = []
    content_reasoning:   str = ""
    # 视觉分析
    visual_risk_score:   float = 0.0
    is_phishing:         bool = False
    impersonates:        Optional[str] = None
    visual_features:     List[str] = []
    visual_description:  str = ""
    # AI 侦查报告
    ai_report:           str = ""


class IntelReport(BaseModel):
    """完整情报研判报告"""
    report_id:       str
    url:             str
    analyzed_at:     datetime = Field(default_factory=datetime.utcnow)
    raw_intel:       RawIntelligence
    features:        FeatureVector
    wras:            WRASResult
    disposal:        DisposalPlan
    gemini:          Optional[GeminiAnalysis] = None
    analyst_notes:   str = ""
    evidence_urls:   List[str] = []


# ─── API 请求/响应 ─────────────────────────────────────────────
class AnalysisRequest(BaseModel):
    url:            str
    priority:       str = "normal"    # normal / urgent
    analyst_id:     Optional[str] = None
    extra_keywords: List[str] = []    # 案情补充关键词
    ai_engine:      str = "auto"      # auto / gemini / deepseek

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("URL 不能为空")
        if not _URL_RE.match(v):
            raise ValueError(f"URL 格式不合法: {v}")
        return v


class AnalysisResponse(BaseModel):
    success:   bool
    report_id: str
    report:    Optional[IntelReport] = None
    error:     Optional[str]         = None
    elapsed_s: float                 = 0.0
