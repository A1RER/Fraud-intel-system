import { useState } from 'react'
import type {
  InputType, FraudAnalysisResponse, FraudRiskResult,
  AIAnalysis, IntelReport, FeatureVector,
} from '../types'
import { RISK_CONFIG, WRAS_LEVEL_CONFIG, INPUT_TABS } from '../constants'
import { IntelRow, FeatureBar } from '../components/common'

export default function AnalyzePage() {
  const [inputType, setInputType]     = useState<InputType>('recruitment')
  const [content, setContent]         = useState('')
  const [companyName, setCompanyName] = useState('')
  const [urlField, setUrlField]       = useState('')
  const [loading, setLoading]         = useState(false)
  const [result, setResult]           = useState<FraudAnalysisResponse | null>(null)
  const [error, setError]             = useState<string | null>(null)

  const [aiLoading, setAiLoading] = useState<string | null>(null)
  const [aiResult, setAiResult]     = useState<AIAnalysis | null>(null)

  function getMainContent(): string {
    if (inputType === 'company') return companyName.trim()
    if (inputType === 'url') return urlField.trim()
    return content.trim()
  }

  async function handleAnalyze() {
    const main = getMainContent()
    if (!main) return

    setLoading(true)
    setError(null)
    setResult(null)
    setAiResult(null)

    try {
      const body: Record<string, unknown> = { input_type: inputType, content: main }
      if (inputType !== 'company' && companyName.trim()) body.company_name = companyName.trim()
      if (inputType !== 'url' && urlField.trim()) body.url = urlField.trim()

      const res = await fetch('/api/fraud-analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      if (!res.ok) throw new Error(`服务器错误 ${res.status}`)
      const data: FraudAnalysisResponse = await res.json()
      setResult(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : '请求失败，请确认后端服务已启动')
    } finally {
      setLoading(false)
    }
  }

  async function handleAIAnalyze(engine: string) {
    if (!result?.report_id) return
    setAiLoading(engine)
    setError(null)
    try {
      const submitRes = await fetch('/api/ai-analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ report_id: result.report_id, ai_engine: engine }),
      })
      if (!submitRes.ok) {
        const text = await submitRes.text()
        throw new Error(`提交失败 ${submitRes.status}：${text.slice(0, 200)}`)
      }
      const submitData = await submitRes.json()
      if (!submitData.task_id) {
        if (submitData.success && submitData.ai_analysis) setAiResult(submitData.ai_analysis)
        else setError(submitData.error ?? 'AI 分析失败')
        return
      }
      const taskId: string = submitData.task_id
      for (let i = 0; i < 120; i++) {
        await new Promise(r => setTimeout(r, 3000))
        const pollRes = await fetch(`/api/ai-task/${taskId}`)
        if (!pollRes.ok) continue
        const pollData = await pollRes.json()
        if (pollData.status === 'done') {
          if (pollData.success && pollData.ai_analysis) setAiResult(pollData.ai_analysis)
          else setError(pollData.error ?? 'AI 分析失败')
          return
        }
      }
      setError('AI 分析超时，请重试')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'AI 请求失败')
    } finally {
      setAiLoading(null)
    }
  }

  const currentTab = INPUT_TABS.find(t => t.key === inputType)!
  const hasContent = !!getMainContent()

  return (
    <main className="max-w-4xl mx-auto px-6 py-8 space-y-6">
      {/* 标签页切换 */}
      <div className="flex gap-1 bg-slate-900 rounded-xl p-1">
        {INPUT_TABS.map(tab => (
          <button
            key={tab.key}
            onClick={() => setInputType(tab.key)}
            className={`flex-1 flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-medium transition-all cursor-pointer
              ${inputType === tab.key
                ? 'bg-blue-600 text-white shadow-lg'
                : 'text-slate-500 hover:text-slate-300 hover:bg-slate-800'}`}
          >
            <span>{tab.icon}</span>
            <span>{tab.label}</span>
          </button>
        ))}
      </div>

      {/* 主输入区 */}
      <div className="space-y-3">
        {(inputType === 'recruitment' || inputType === 'chat') && (
          <textarea value={content} onChange={e => setContent(e.target.value)} placeholder={currentTab.placeholder} disabled={loading} rows={6}
            className="w-full bg-slate-900 border border-slate-700 rounded-lg px-4 py-3 text-slate-200 placeholder-slate-600 resize-y focus:outline-none focus:border-blue-500 disabled:opacity-50" />
        )}
        {inputType === 'company' && (
          <input type="text" value={companyName} onChange={e => setCompanyName(e.target.value)} onKeyDown={e => e.key === 'Enter' && handleAnalyze()} placeholder={currentTab.placeholder} disabled={loading}
            className="w-full bg-slate-900 border border-slate-700 rounded-lg px-4 py-3 text-slate-200 placeholder-slate-600 focus:outline-none focus:border-blue-500 disabled:opacity-50" />
        )}
        {inputType === 'url' && (
          <input type="text" value={urlField} onChange={e => setUrlField(e.target.value)} onKeyDown={e => e.key === 'Enter' && handleAnalyze()} placeholder={currentTab.placeholder} disabled={loading}
            className="w-full bg-slate-900 border border-slate-700 rounded-lg px-4 py-3 text-slate-200 placeholder-slate-600 focus:outline-none focus:border-blue-500 disabled:opacity-50" />
        )}
        {(inputType === 'recruitment' || inputType === 'chat') && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <input type="text" value={companyName} onChange={e => setCompanyName(e.target.value)} placeholder="公司名称（可选补充）" disabled={loading}
              className="bg-slate-900 border border-slate-700 rounded-lg px-4 py-2.5 text-slate-200 placeholder-slate-600 text-sm focus:outline-none focus:border-blue-500 disabled:opacity-50" />
            <input type="text" value={urlField} onChange={e => setUrlField(e.target.value)} placeholder="相关链接（可选补充）" disabled={loading}
              className="bg-slate-900 border border-slate-700 rounded-lg px-4 py-2.5 text-slate-200 placeholder-slate-600 text-sm focus:outline-none focus:border-blue-500 disabled:opacity-50" />
          </div>
        )}
        <button onClick={handleAnalyze} disabled={loading || !hasContent}
          className="w-full bg-blue-600 hover:bg-blue-500 disabled:bg-slate-800 disabled:text-slate-600 text-white py-3 rounded-lg font-medium transition-colors cursor-pointer text-sm">
          {loading ? '⏳ 正在分析中...' : '▶ 开始识别'}
        </button>
      </div>

      {loading && (
        <div className="text-center py-12 text-slate-500">
          <div className="text-5xl mb-4 animate-pulse">👁️</div>
          <p className="text-sm">正在执行多维度风险识别分析...</p>
          <p className="text-xs mt-2 text-slate-700">
            {inputType === 'url' ? 'OSINT 采集 → 特征工程 → WRAS 评分 → AI 分析' : '关键词匹配 → 话术识别 → 风险评估'}
          </p>
        </div>
      )}

      {error && <div className="bg-red-950/50 border border-red-800 rounded-lg p-4 text-red-400 text-sm">⚠️ {error}</div>}
      {result && !result.success && <div className="bg-red-950/50 border border-red-800 rounded-lg p-4 text-red-400 text-sm">⚠️ 分析失败：{result.error}</div>}
      {result?.success && result.risk && <FraudResultView risk={result.risk} reportId={result.report_id} elapsed={result.elapsed_s} />}
      {result?.success && result.wras_report && <WRASDetailView report={result.wras_report} aiResult={aiResult} aiLoading={aiLoading} onAIAnalyze={handleAIAnalyze} />}
    </main>
  )
}


// ── 诈骗风险结果 ──────────────────────────────────────────────────
function FraudResultView({ risk, reportId, elapsed }: { risk: FraudRiskResult; reportId: string; elapsed: number }) {
  const cfg = RISK_CONFIG[risk.risk_level] ?? RISK_CONFIG.SAFE
  return (
    <div className="space-y-4">
      <div className={`${cfg.bg} ${cfg.border} border rounded-xl p-6`}>
        <div className="flex items-start justify-between">
          <div>
            <p className="text-slate-500 text-xs mb-2 font-mono tracking-wider">风险评分</p>
            <p className={`${cfg.color} text-6xl font-bold font-mono leading-none`}>{risk.risk_score.toFixed(1)}</p>
            <p className={`${cfg.color} mt-3 text-lg`}>{cfg.emoji} {cfg.label}</p>
            <p className="text-slate-400 text-sm mt-2">{risk.summary}</p>
          </div>
          <div className="text-right text-sm text-slate-600 space-y-1 font-mono">
            <p>置信度 {(risk.confidence * 100).toFixed(0)}%</p>
            <p className="text-slate-700 text-xs mt-3">{reportId}</p>
            <p className="text-slate-700 text-xs">耗时 {elapsed.toFixed(2)}s</p>
          </div>
        </div>
      </div>

      {risk.fraud_types.length > 0 && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <h2 className="text-slate-500 text-xs font-mono tracking-wider mb-3">识别到的诈骗类型</h2>
          <div className="flex flex-wrap gap-2">
            {risk.fraud_types.map((ft, i) => <span key={i} className="bg-red-950 text-red-300 border border-red-800 px-3 py-1 rounded-full text-sm font-medium">{ft}</span>)}
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {risk.evidence.length > 0 && (
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
            <h2 className="text-slate-500 text-xs font-mono tracking-wider mb-3">证据链</h2>
            <div className="space-y-2">
              {risk.evidence.map((ev, i) => <div key={i} className="flex gap-2 text-sm"><span className="text-orange-400 shrink-0">▸</span><span className="text-slate-300">{ev}</span></div>)}
            </div>
          </div>
        )}
        {risk.keyword_hits.length > 0 && (
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
            <h2 className="text-slate-500 text-xs font-mono tracking-wider mb-3">命中关键词</h2>
            <div className="flex flex-wrap gap-2">
              {risk.keyword_hits.map((kw, i) => <span key={i} className="bg-orange-950/50 text-orange-300 border border-orange-800/50 px-2.5 py-0.5 rounded text-sm">{kw}</span>)}
            </div>
          </div>
        )}
      </div>

      {risk.suggestions.length > 0 && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <h2 className="text-slate-500 text-xs font-mono tracking-wider mb-3">防范建议</h2>
          <ol className="space-y-2">
            {risk.suggestions.map((s, i) => <li key={i} className="flex gap-3 text-sm text-slate-400"><span className="text-blue-400 font-bold shrink-0">{i + 1}</span><span>{s}</span></li>)}
          </ol>
        </div>
      )}

      {risk.ai_analysis && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <h2 className="text-slate-500 text-xs font-mono tracking-wider mb-3">AI 深度分析</h2>
          <div className="text-slate-300 text-sm leading-relaxed whitespace-pre-wrap">{risk.ai_analysis}</div>
        </div>
      )}
    </div>
  )
}


// ── WRAS 详细报告 ──────────────────────────────────────────────────
function WRASDetailView({ report, aiResult, aiLoading, onAIAnalyze }: {
  report: IntelReport; aiResult: AIAnalysis | null; aiLoading: string | null; onAIAnalyze: (engine: string) => void
}) {
  const { wras, disposal, raw_intel, features } = report
  const level = WRAS_LEVEL_CONFIG[wras.risk_level]

  return (
    <div className="space-y-4">
      <div className="border-t border-slate-800 pt-4">
        <p className="text-slate-600 text-xs font-mono tracking-widest mb-4">▼ 网站 OSINT 详细分析</p>
      </div>

      <div className={`${level.bg} ${level.border} border rounded-xl p-6`}>
        <div className="flex items-start justify-between">
          <div>
            <p className="text-slate-500 text-xs mb-2 font-mono tracking-wider">WRAS 综合风险评分</p>
            <p className={`${level.color} text-7xl font-bold font-mono leading-none`}>{wras.final_score.toFixed(1)}</p>
            <p className={`${level.color} mt-3 text-lg`}>{level.emoji} {wras.risk_level} — {level.label}</p>
          </div>
          <div className="text-right text-sm text-slate-600 space-y-1 font-mono">
            <p>原始分 {wras.raw_score.toFixed(1)}</p>
            <p>置信度 {(wras.confidence_coeff * 100).toFixed(0)}%</p>
            <p className="text-slate-700 text-xs mt-3">{report.report_id}</p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <h2 className="text-slate-500 text-xs font-mono tracking-wider mb-3">处置预案</h2>
          <p className="text-slate-300 text-sm mb-4">{disposal.action}</p>
          <ol className="space-y-2">
            {disposal.steps.map((step, i) => <li key={i} className="flex gap-3 text-sm text-slate-500"><span className={`${level.color} font-bold shrink-0`}>{i + 1}</span><span>{step}</span></li>)}
          </ol>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <h2 className="text-slate-500 text-xs font-mono tracking-wider mb-3">基础情报</h2>
          <div className="space-y-2 text-sm">
            <IntelRow label="域名" value={raw_intel.domain} />
            <IntelRow label="注册时长" value={raw_intel.domain_age_days != null ? `${raw_intel.domain_age_days} 天` : '未知'} />
            <IntelRow label="ICP 备案" value={raw_intel.icp_record ?? '⚠️ 无备案'} warn={!raw_intel.icp_record} />
            <IntelRow label="服务器" value={`${raw_intel.server_country ?? '未知'} / ${raw_intel.server_isp ?? '—'}`} />
            <IntelRow label="SSL 证书" value={raw_intel.ssl_valid ? (raw_intel.ssl_self_signed ? '⚠️ 自签名' : '有效') : '⚠️ 无效'} warn={!raw_intel.ssl_valid || raw_intel.ssl_self_signed} />
            <IntelRow label="WHOIS 隐私" value={raw_intel.whois_privacy ? '⚠️ 已隐藏' : '正常'} warn={raw_intel.whois_privacy} />
            <IntelRow label="黑名单" value={raw_intel.blacklist_hit ? '⚠️ 命中' : '未命中'} warn={raw_intel.blacklist_hit} />
            <IntelRow label="投诉量" value={`${raw_intel.complaint_count} 条`} />
          </div>
        </div>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
        <h2 className="text-slate-500 text-xs font-mono tracking-wider mb-4">风险特征热力图</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-1">
          {(Object.entries({
            keyword_risk_score: '风险话术密度', public_sentiment_neg: '负面舆情强度',
            phishing_visual_sim: '钓鱼视觉相似度', icp_missing: 'ICP 备案缺失',
            complaint_count_norm: '投诉量', domain_age_days: '域名注册时长',
            ip_overseas: '境外服务器', ssl_self_signed: 'SSL 自签名',
            resource_load_anomaly: '页面资源异常', whois_privacy_protected: 'WHOIS 信息隐藏',
            blacklist_hit: '黑名单命中', ip_cdn_abuse: 'CDN 规避行为',
          }) as [keyof FeatureVector, string][]).map(([key, label]) => (
            <FeatureBar key={key} label={label} value={features[key] as number ?? 0} contrib={wras.feature_contrib[key] ?? 0} />
          ))}
        </div>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
        <h2 className="text-slate-500 text-xs font-mono tracking-wider mb-4">AI 深度分析（按需调用）</h2>
        {!aiResult && !aiLoading && (
          <div className="space-y-3">
            <p className="text-slate-500 text-sm">基础分析已完成。如需 AI 深度语义分析，请选择引擎：</p>
            <div className="flex gap-3">
              <button onClick={() => onAIAnalyze('deepseek')} className="bg-blue-900/50 hover:bg-blue-800/50 border border-blue-700 text-blue-300 px-5 py-2.5 rounded-lg text-sm font-medium transition-colors cursor-pointer">✦ DeepSeek 分析</button>
            </div>
          </div>
        )}
        {aiLoading && (
          <div className="text-center py-8 text-slate-500">
            <div className="text-3xl mb-3 animate-pulse">✦</div>
            <p className="text-sm">正在执行 DeepSeek AI 深度分析...</p>
          </div>
        )}
        {aiResult && <AIResultView aiResult={aiResult} />}
      </div>
    </div>
  )
}


// ── AI 结果 ──────────────────────────────────────────────────
function AIResultView({ aiResult }: { aiResult: AIAnalysis }) {
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between bg-slate-950 rounded-lg px-4 py-2 border border-green-900/50">
        <div className="flex items-center gap-2">
          <span className="text-lg">✦</span>
          <span className="text-green-400 font-medium text-sm">Powered by {aiResult.model_name || 'AI Engine'}</span>
        </div>
        <span className="text-slate-600 text-xs font-mono">耗时 {aiResult.ai_elapsed_s.toFixed(1)}s</span>
      </div>

      {(aiResult.content_risk_score > 0 || aiResult.content_reasoning) && (
        <div className="bg-slate-950 border border-slate-800 rounded-lg p-4">
          <h3 className="text-slate-400 text-xs font-mono mb-3">AI 内容语义分析</h3>
          <div className="flex items-center gap-4">
            <span className={`text-3xl font-bold font-mono ${aiResult.content_risk_score > 0.7 ? 'text-red-400' : aiResult.content_risk_score > 0.4 ? 'text-orange-400' : aiResult.content_risk_score > 0.2 ? 'text-yellow-400' : 'text-green-400'}`}>
              {(aiResult.content_risk_score * 100).toFixed(0)}%
            </span>
            <p className="text-slate-400 text-sm">{aiResult.content_reasoning}</p>
          </div>
          {aiResult.fraud_types.length > 0 && (
            <div className="mt-3 flex flex-wrap gap-2">
              {aiResult.fraud_types.map((ft: string, i: number) => <span key={i} className="bg-red-950 text-red-300 border border-red-800 px-2 py-0.5 rounded-full text-xs">{ft}</span>)}
            </div>
          )}
          {aiResult.key_evidence.length > 0 && (
            <div className="mt-3 space-y-1">
              <p className="text-slate-500 text-xs font-mono">关键证据：</p>
              {aiResult.key_evidence.map((ev: string, i: number) => <p key={i} className="text-slate-400 text-xs leading-relaxed">• {ev}</p>)}
            </div>
          )}
        </div>
      )}

      {aiResult.ai_report && (
        <div className="bg-slate-950 border border-slate-800 rounded-lg p-4">
          <h3 className="text-slate-400 text-xs font-mono mb-3">AI 侦查报告</h3>
          <div className="text-slate-300 text-sm leading-relaxed whitespace-pre-wrap">{aiResult.ai_report}</div>
        </div>
      )}
    </div>
  )
}
