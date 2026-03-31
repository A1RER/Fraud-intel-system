// 这个文件定义了所有数据的"形状"，对应后端 schemas.py 里的 Pydantic 模型
// TypeScript 用 interface / type 来描述对象结构，写代码时会自动提示字段名

export type RiskLevel = 'RED' | 'ORANGE' | 'YELLOW' | 'GREEN'

export interface WRASResult {
  raw_score: number
  confidence_coeff: number
  final_score: number
  risk_level: RiskLevel
  feature_contrib: Record<string, number>
  score_breakdown: Record<string, number>
}

export interface DisposalPlan {
  level: string
  action: string
  urgency: string
  steps: string[]
}

export interface RawIntelligence {
  domain: string
  domain_age_days?: number
  registrar?: string
  whois_privacy: boolean
  icp_record?: string
  ssl_valid: boolean
  ssl_issuer?: string
  ssl_self_signed: boolean
  server_ip?: string
  server_country?: string
  server_isp?: string
  is_cdn: boolean
  complaint_count: number
  blacklist_hit: boolean
  search_snippets: string[]
}

export interface FeatureVector {
  domain_age_days: number
  icp_missing: number
  whois_privacy_protected: number
  ssl_self_signed: number
  ip_overseas: number
  ip_cdn_abuse: number
  keyword_risk_score: number
  phishing_visual_sim: number
  resource_load_anomaly: number
  public_sentiment_neg: number
  complaint_count_norm: number
  blacklist_hit: number
  keyword_hits: Record<string, string[]>
  sentiment_detail?: string
}

export interface GeminiAnalysis {
  model_name: string
  ai_elapsed_s: number
  content_risk_score: number
  fraud_types: string[]
  key_evidence: string[]
  risk_indicators: string[]
  content_reasoning: string
  visual_risk_score: number
  is_phishing: boolean
  impersonates?: string
  visual_features: string[]
  visual_description: string
  ai_report: string
}

export interface IntelReport {
  report_id: string
  url: string
  analyzed_at: string
  wras: WRASResult
  disposal: DisposalPlan
  raw_intel: RawIntelligence
  features: FeatureVector
  gemini?: GeminiAnalysis
}

export interface AnalysisResponse {
  success: boolean
  report_id: string
  elapsed_s: number
  error?: string
  report?: IntelReport
}

export interface AIAnalyzeResponse {
  success: boolean
  error?: string
  gemini?: GeminiAnalysis
}

// ─── 慧眼：招聘诈骗识别 ─────────────────────────────────────────

export type InputType = 'recruitment' | 'chat' | 'company' | 'url'

export interface FraudRiskResult {
  risk_level: string    // HIGH / MEDIUM / LOW / SAFE
  risk_score: number
  fraud_types: string[]
  confidence: number
  summary: string
  evidence: string[]
  suggestions: string[]
  keyword_hits: string[]
  ai_analysis?: string
}

export interface FraudAnalysisResponse {
  success: boolean
  report_id: string
  input_type: string
  risk?: FraudRiskResult
  wras_report?: IntelReport
  error?: string
  elapsed_s: number
}

// ─── 情报库 ─────────────────────────────────────────────────────

export interface IntelRecord {
  id: number
  report_id: string
  input_type: string
  content: string
  company_name?: string
  url?: string
  risk_level: string
  risk_score: number
  fraud_types: string[]
  confidence: number
  summary: string
  evidence: string[]
  keyword_hits: string[]
  suggestions: string[]
  ai_analysis?: string
  created_at: string
}

export interface RiskyCompany {
  id: number
  company_name: string
  risk_level: string
  risk_score: number
  fraud_types: string[]
  hit_count: number
  evidence: string[]
  first_seen: string
  last_seen: string
}

export interface FraudPattern {
  fraud_type: string
  total_count: number
  high_count: number
  recent_keywords: string[]
}

export interface TrendDay {
  date: string
  count: number
  high_count: number
}

export interface IntelStats {
  total_records: number
  total_companies: number
  level_stats: Record<string, number>
  fraud_patterns: FraudPattern[]
  trend_7d: TrendDay[]
  top_companies: { company_name: string; hit_count: number; risk_level: string; risk_score: number }[]
}
