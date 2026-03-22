# backend/modules/feature_engineer.py
"""
模块二：特征工程与信号增强
将原始情报转换为标准化特征向量（值域 0~1，越高风险越大）
维度：静态 | 网络 | 内容（NLP+pHash）| 舆情
"""
import math
import re
from typing import Dict, List, Optional, Tuple
from loguru import logger

from backend.models.schemas import RawIntelligence, FeatureVector
from config.settings import RISK_KEYWORDS, KEYWORD_WEIGHTS, OFFICIAL_PAGE_HASHES

try:
    from PIL import Image
    import imagehash
    import base64
    import io
    IMAGEHASH_AVAILABLE = True
except ImportError:
    IMAGEHASH_AVAILABLE = False


# ── 静态维度 ──────────────────────────────────────────────────
def feat_domain_age(age_days: Optional[int]) -> float:
    if age_days is None: return 0.7
    if age_days < 7:     return 1.0
    if age_days < 30:    return 0.9
    if age_days < 90:    return 0.7
    if age_days < 180:   return 0.5
    if age_days < 365:   return 0.3
    if age_days < 730:   return 0.15
    return 0.05

def feat_icp_missing(icp_record: Optional[str]) -> float:
    return 0.0 if icp_record else 1.0

def feat_whois_privacy(whois_privacy: bool) -> float:
    return 0.6 if whois_privacy else 0.0

def feat_ssl_self_signed(ssl_self_signed: bool, ssl_valid: bool) -> float:
    if ssl_self_signed: return 0.8
    if not ssl_valid:   return 0.9
    return 0.0


# ── 网络维度 ──────────────────────────────────────────────────
SUSPICIOUS_COUNTRIES = {"Cambodia","Myanmar","Philippines","Laos","Vietnam","Malaysia","Thailand"}
CHINA_MAINLAND = {"China", "CN"}

def feat_ip_overseas(country: Optional[str]) -> float:
    if not country:               return 0.4
    if country in CHINA_MAINLAND: return 0.0
    if country in SUSPICIOUS_COUNTRIES: return 1.0
    return 0.6

def feat_ip_cdn_abuse(is_cdn: bool, redirect_count: int) -> float:
    score = (0.3 if is_cdn else 0.0)
    if redirect_count >= 3: score += 0.3
    if redirect_count >= 5: score += 0.2
    return min(score, 1.0)

def feat_resource_anomaly(errors: int, total: int) -> float:
    if total == 0: return 0.3
    rate = errors / total
    if rate > 0.5: return 1.0
    if rate > 0.3: return 0.7
    if rate > 0.1: return 0.4
    return rate * 2.0


# ── 内容维度：关键词 NLP ──────────────────────────────────────
class KeywordAnalyzer:
    @staticmethod
    def analyze(text: str, extra_kw: List[str] = []) -> Tuple[float, Dict[str, List[str]]]:
        if not text:
            return 0.0, {}
        text_lower = text.lower()
        hits: Dict[str, List[str]] = {"high": [], "medium": [], "low": []}
        raw_score = 0.0
        for level, keywords in RISK_KEYWORDS.items():
            for kw in keywords:
                count = text_lower.count(kw)
                if count > 0:
                    hits[level].append(f"{kw}(x{count})")
                    raw_score += count * KEYWORD_WEIGHTS[level]
        for kw in extra_kw:
            count = text_lower.count(kw.lower())
            if count > 0:
                hits["high"].append(f"[自定义]{kw}(x{count})")
                raw_score += count * 1.2
        normalized = 1 / (1 + math.exp(-0.3 * (raw_score - 5)))
        return round(normalized, 4), hits


# ── 内容维度：感知哈希（pHash 钓鱼检测）────────────────────────
class VisualSimilarityAnalyzer:
    @staticmethod
    def analyze(screenshot_b64: Optional[str]) -> float:
        if not screenshot_b64 or not IMAGEHASH_AVAILABLE:
            return 0.0
        try:
            img_data = base64.b64decode(screenshot_b64)
            img = Image.open(io.BytesIO(img_data))
            target_hash = imagehash.phash(img)
            max_sim = 0.0
            for site, hash_str in OFFICIAL_PAGE_HASHES.items():
                try:
                    ref_hash = imagehash.hex_to_hash(hash_str)
                    distance = target_hash - ref_hash
                    sim = 1.0 - (distance / 64.0)
                    if sim > max_sim:
                        max_sim = sim
                except Exception:
                    continue
            return max(0.0, (max_sim - 0.85) / 0.15) if max_sim > 0.85 else 0.0
        except Exception as e:
            logger.warning(f"pHash 分析失败: {e}")
            return 0.0


# ── 舆情维度 ──────────────────────────────────────────────────
class SentimentAnalyzer:
    NEG_PATTERNS = [
        (r"骗局|诈骗|骗子|欺骗|坑人", 1.0),
        (r"提现失败|无法提现|提不出来", 0.9),
        (r"账号被封|被冻结|跑路", 0.95),
        (r"投诉|举报|维权", 0.7),
        (r"打不开|联系不上|失联", 0.6),
        (r"怀疑|疑似|可能是骗", 0.5),
    ]

    @classmethod
    def analyze(cls, snippets: List[str]) -> Tuple[float, str]:
        if not snippets:
            return 0.0, "无舆情数据"
        all_text = " ".join(snippets)
        total_score = 0.0
        hit_patterns = []
        for pattern, weight in cls.NEG_PATTERNS:
            if re.search(pattern, all_text):
                total_score += weight
                hit_patterns.append(pattern.split("|")[0])
        normalized = min(total_score / 3.0, 1.0)
        detail = f"命中风险话术：{', '.join(hit_patterns)}" if hit_patterns else "未发现明显负面舆情"
        return round(normalized, 4), detail

def feat_complaint_count(count: int) -> float:
    if count == 0:    return 0.0
    if count >= 100:  return 1.0
    return math.log(count + 1) / math.log(101)

def feat_blacklist(hit: bool) -> float:
    return 1.0 if hit else 0.0


# ── 主入口 ─────────────────────────────────────────────────────
class FeatureEngineer:
    @staticmethod
    def extract(intel: RawIntelligence, extra_keywords: List[str] = []) -> FeatureVector:
        logger.info(f"[FE] 开始特征提取: {intel.domain}")
        combined_text = " ".join(filter(None, [
            intel.page_text or "", intel.page_title or "",
            *intel.search_snippets, *intel.social_mentions,
        ]))
        kw_score, kw_hits = KeywordAnalyzer.analyze(combined_text, extra_keywords)
        visual_sim = VisualSimilarityAnalyzer.analyze(intel.screenshot_b64)
        sentiment_score, sentiment_detail = SentimentAnalyzer.analyze(
            intel.search_snippets + intel.social_mentions
        )
        fv = FeatureVector(
            domain_age_days=feat_domain_age(intel.domain_age_days),
            icp_missing=feat_icp_missing(intel.icp_record),
            whois_privacy_protected=feat_whois_privacy(intel.whois_privacy),
            ssl_self_signed=feat_ssl_self_signed(intel.ssl_self_signed, intel.ssl_valid),
            ip_overseas=feat_ip_overseas(intel.server_country),
            ip_cdn_abuse=feat_ip_cdn_abuse(intel.is_cdn, len(intel.redirect_chain)),
            keyword_risk_score=kw_score,
            phishing_visual_sim=visual_sim,
            resource_load_anomaly=feat_resource_anomaly(intel.resource_errors, intel.total_resources),
            public_sentiment_neg=sentiment_score,
            complaint_count_norm=feat_complaint_count(intel.complaint_count),
            blacklist_hit=feat_blacklist(intel.blacklist_hit),
            keyword_hits=kw_hits,
            sentiment_detail=sentiment_detail,
        )
        logger.success(f"[FE] 特征提取完成: {intel.domain}")
        return fv
