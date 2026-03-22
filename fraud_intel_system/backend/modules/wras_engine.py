# backend/modules/wras_engine.py
"""
模块三：WRAS 加权风险评分引擎
公式：Risk_Score = Σ(W_i × F_i) × C_trust

CFAR 思想借鉴：
  信号（涉诈特征） vs 噪声（正常网站特征）
  置信度系数 C_trust 类比 CFAR 中的自适应门限
"""
from datetime import datetime, timezone
from typing import Dict
from loguru import logger

from backend.models.schemas import FeatureVector, WRASResult, RiskLevelEnum
from config.settings import (
    FEATURE_WEIGHTS, RISK_THRESHOLDS, CONFIDENCE_DECAY_HOURS, CONFIDENCE_MIN
)


def _calc_confidence(collected_at: datetime, source_count: int) -> float:
    """
    置信度系数 C_trust 计算
    
    影响因子：
    1. 时效性：情报采集时间越久，置信度衰减
    2. 情报源数量：多源交叉验证，置信度提升
    
    C_trust ∈ [CONFIDENCE_MIN, 1.0]
    """
    if collected_at.tzinfo is None:
        collected_at = collected_at.replace(tzinfo=timezone.utc)
    
    now = datetime.now(timezone.utc)
    age_hours = (now - collected_at).total_seconds() / 3600
    
    # 时效性衰减（超过 CONFIDENCE_DECAY_HOURS 开始线性衰减）
    if age_hours <= CONFIDENCE_DECAY_HOURS:
        time_factor = 1.0
    else:
        decay = (age_hours - CONFIDENCE_DECAY_HOURS) / (CONFIDENCE_DECAY_HOURS * 2)
        time_factor = max(1.0 - decay, CONFIDENCE_MIN)
    
    # 多源加权（每增加一个来源，置信度 +5%，上限 1.0）
    source_factor = min(1.0 + (source_count - 1) * 0.05, 1.2)
    
    return round(min(time_factor * source_factor, 1.0), 4)


def _determine_risk_level(score: float) -> RiskLevelEnum:
    """根据最终分值确定风险等级"""
    if score >= RISK_THRESHOLDS["RED"]:    return RiskLevelEnum.RED
    if score >= RISK_THRESHOLDS["ORANGE"]: return RiskLevelEnum.ORANGE
    if score >= RISK_THRESHOLDS["YELLOW"]: return RiskLevelEnum.YELLOW
    return RiskLevelEnum.GREEN


def _score_breakdown(features: FeatureVector, weights: Dict[str, float]) -> Dict[str, float]:
    """
    各维度得分汇总
    用于生成可解释性热力图
    """
    fv_dict = features.model_dump()
    breakdown = {}
    
    dimension_groups = {
        "域名注册维度": ["domain_age_days", "icp_missing", "whois_privacy_protected", "ssl_self_signed"],
        "网络地理维度": ["ip_overseas", "ip_cdn_abuse"],
        "页面内容维度": ["keyword_risk_score", "phishing_visual_sim", "resource_load_anomaly"],
        "舆情维度":     ["public_sentiment_neg", "complaint_count_norm", "blacklist_hit"],
    }
    
    for dim, feat_names in dimension_groups.items():
        dim_score = sum(
            weights.get(f, 0) * fv_dict.get(f, 0.0) * 100
            for f in feat_names
        )
        breakdown[dim] = round(dim_score, 2)
    
    return breakdown


class WRASEngine:
    """
    加权风险评分引擎（Weighted Risk Assessment Score）
    
    设计哲学（借鉴雷达 CFAR）：
    - W_i 类比"检测权重"，由业务专家（警校方）提供
    - F_i 类比"回波强度"，由特征工程标准化输出
    - C_trust 类比"自适应门限"，基于情报时效性动态调整
    - 最终分值 × 100 映射到 0~100 风险评分区间
    """
    
    def __init__(self, weights: Dict[str, float] = None):
        self.weights = weights or FEATURE_WEIGHTS
        
    def score(
        self, 
        features: FeatureVector, 
        collected_at: datetime = None,
        source_count: int = 1
    ) -> WRASResult:
        
        logger.info("[WRAS] 开始风险评分计算")
        
        if collected_at is None:
            collected_at = datetime.now(timezone.utc)
        
        fv_dict = features.model_dump()
        
        # ── 核心公式：Σ(W_i × F_i) ─────────────────────────────
        feature_contrib: Dict[str, float] = {}
        raw_sum = 0.0
        
        for feat_name, weight in self.weights.items():
            feat_val = fv_dict.get(feat_name, 0.0)
            if not isinstance(feat_val, (int, float)):
                continue
            contribution = weight * feat_val * 100    # 映射到百分制
            feature_contrib[feat_name] = round(contribution, 3)
            raw_sum += contribution
        
        raw_score = round(min(raw_sum, 100.0), 2)
        
        # ── 置信度系数 ──────────────────────────────────────────
        c_trust = _calc_confidence(collected_at, source_count)
        
        # ── 最终分值 ─────────────────────────────────────────────
        # 注意：对极高分（> 85）置信度不缩减，保证高危案例不被低估
        if raw_score >= 85:
            final_score = raw_score   # 极高危，不折扣
        else:
            final_score = round(raw_score * c_trust, 2)
        
        risk_level = _determine_risk_level(final_score)
        score_breakdown = _score_breakdown(features, self.weights)
        
        result = WRASResult(
            raw_score=raw_score,
            confidence_coeff=c_trust,
            final_score=final_score,
            risk_level=risk_level,
            feature_contrib=feature_contrib,
            score_breakdown=score_breakdown,
        )
        
        logger.success(
            f"[WRAS] 评分完成: raw={raw_score:.1f} × C_trust={c_trust:.3f} "
            f"= final={final_score:.1f} [{risk_level}]"
        )
        return result
