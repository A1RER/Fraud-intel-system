// React 的核心概念：useState
// useState 用来存储"会变化的数据"，每次数据变化，页面自动重新渲染
import { useState } from 'react'
import type { AnalysisResponse, RiskLevel } from './types'

// ── 风险等级的颜色/样式配置 ──────────────────────────────────────
const LEVEL_CONFIG: Record<RiskLevel, {
  color: string
  bg: string
  border: string
  emoji: string
  label: string
}> = {
  RED:    { color: 'text-red-400',    bg: 'bg-red-950/50',    border: 'border-red-800',    emoji: '🔴', label: '高危' },
  ORANGE: { color: 'text-orange-400', bg: 'bg-orange-950/50', border: 'border-orange-800', emoji: '🟠', label: '中高风险' },
  YELLOW: { color: 'text-yellow-400', bg: 'bg-yellow-950/50', border: 'border-yellow-800', emoji: '🟡', label: '疑似风险' },
  GREEN:  { color: 'text-green-400',  bg: 'bg-green-950/50',  border: 'border-green-800',  emoji: '🟢', label: '暂无风险' },
}

// ── 主组件 ──────────────────────────────────────────────────────
// React 里每个"组件"就是一个返回 JSX（类似 HTML）的函数
export default function App() {
  // useState<类型>(初始值) → 返回 [当前值, 修改函数]
  const [url, setUrl]         = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult]   = useState<AnalysisResponse | null>(null)
  const [error, setError]     = useState<string | null>(null)

  // 点击"开始研判"时执行的函数
  async function handleAnalyze() {
    if (!url.trim()) return

    setLoading(true)
    setError(null)
    setResult(null)

    try {
      // fetch 调用后端 API，因为 vite.config.ts 里配置了 proxy，
      // 这里的 /api/analyze 会被转发到 http://localhost:8000/api/analyze
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url.trim() }),
      })

      if (!response.ok) {
        throw new Error(`服务器错误 ${response.status}`)
      }

      const data: AnalysisResponse = await response.json()
      setResult(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : '请求失败，请确认后端服务已启动')
    } finally {
      // finally 无论成功失败都会执行，用来关闭 loading 状态
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-300">

      {/* 顶部标题栏 */}
      <header className="border-b border-slate-800 px-6 py-4">
        <div className="max-w-4xl mx-auto flex items-center gap-3">
          <span className="text-2xl">🔍</span>
          <div>
            <h1 className="text-blue-400 font-bold tracking-widest text-sm">
              涉诈网站智能研判系统
            </h1>
            <p className="text-slate-600 text-xs font-mono">
              FRAUD WEBSITE ASSESSMENT SYSTEM v2.0 | 仅限授权人员使用
            </p>
          </div>
        </div>
      </header>

      {/* 主内容区 */}
      <main className="max-w-4xl mx-auto px-6 py-12 space-y-6">

        {/* 输入区域 */}
        <div className="flex gap-3">
          <input
            type="text"
            value={url}
            // onChange 在每次输入时触发，更新 url 状态
            onChange={(e) => setUrl(e.target.value)}
            // 支持回车触发分析
            onKeyDown={(e) => e.key === 'Enter' && handleAnalyze()}
            placeholder="输入目标网址，如：suspicious-invest.com"
            disabled={loading}
            className="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-4 py-3
                       text-slate-200 placeholder-slate-600
                       focus:outline-none focus:border-blue-500
                       disabled:opacity-50"
          />
          <button
            onClick={handleAnalyze}
            disabled={loading || !url.trim()}
            className="bg-blue-600 hover:bg-blue-500 disabled:bg-slate-800 disabled:text-slate-600
                       text-white px-6 py-3 rounded-lg font-medium transition-colors cursor-pointer"
          >
            {loading ? '分析中...' : '▶ 开始研判'}
          </button>
        </div>

        {/* Loading 状态 */}
        {/* 在 JSX 里，{条件 && <组件/>} 表示"条件为真时才渲染" */}
        {loading && (
          <div className="text-center py-16 text-slate-500">
            <div className="text-5xl mb-4 animate-pulse">⚡</div>
            <p className="text-sm">正在执行多维度情报采集与研判分析...</p>
            <p className="text-xs mt-2 text-slate-700">OSINT 采集 → 特征工程 → WRAS 评分 → AI 分析</p>
          </div>
        )}

        {/* 错误提示 */}
        {error && (
          <div className="bg-red-950/50 border border-red-800 rounded-lg p-4 text-red-400 text-sm">
            ⚠️ {error}
          </div>
        )}

        {/* 分析失败 */}
        {result && !result.success && (
          <div className="bg-red-950/50 border border-red-800 rounded-lg p-4 text-red-400 text-sm">
            ⚠️ 分析失败：{result.error}
          </div>
        )}

        {/* 分析结果 */}
        {result?.success && result.report && (
          <ResultView result={result} />
        )}

      </main>
    </div>
  )
}

// ── 结果展示组件 ──────────────────────────────────────────────────
// 把结果展示拆成独立组件，让 App 保持简洁
// props（属性）是父组件传给子组件的数据，类似函数的参数
function ResultView({ result }: { result: AnalysisResponse }) {
  const report  = result.report!
  const { wras, disposal, raw_intel, features } = report
  const level   = LEVEL_CONFIG[wras.risk_level]

  return (
    <div className="space-y-4">

      {/* 风险评分卡片 */}
      <div className={`${level.bg} ${level.border} border rounded-xl p-6`}>
        <div className="flex items-start justify-between">
          <div>
            <p className="text-slate-500 text-xs mb-2 font-mono tracking-wider">WRAS 综合风险评分</p>
            <p className={`${level.color} text-7xl font-bold font-mono leading-none`}>
              {wras.final_score.toFixed(1)}
            </p>
            <p className={`${level.color} mt-3 text-lg`}>
              {level.emoji} {wras.risk_level} — {level.label}
            </p>
          </div>
          <div className="text-right text-sm text-slate-600 space-y-1 font-mono">
            <p>原始分 {wras.raw_score.toFixed(1)}</p>
            <p>置信度 {(wras.confidence_coeff * 100).toFixed(0)}%</p>
            <p className="text-slate-700 text-xs mt-3">{report.report_id}</p>
            <p className="text-slate-700 text-xs">耗时 {result.elapsed_s.toFixed(1)}s</p>
          </div>
        </div>
      </div>

      {/* 两列布局：处置预案 + 基础情报 */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">

        {/* 处置预案 */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <h2 className="text-slate-500 text-xs font-mono tracking-wider mb-3">处置预案</h2>
          <p className="text-slate-300 text-sm mb-4">{disposal.action}</p>
          <ol className="space-y-2">
            {disposal.steps.map((step, i) => (
              <li key={i} className="flex gap-3 text-sm text-slate-500">
                <span className={`${level.color} font-bold shrink-0`}>{i + 1}</span>
                <span>{step}</span>
              </li>
            ))}
          </ol>
        </div>

        {/* 基础情报 */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <h2 className="text-slate-500 text-xs font-mono tracking-wider mb-3">基础情报</h2>
          <div className="space-y-2 text-sm">
            <IntelRow label="域名"       value={raw_intel.domain} />
            <IntelRow label="注册时长"   value={raw_intel.domain_age_days != null ? `${raw_intel.domain_age_days} 天` : '未知'} />
            <IntelRow label="ICP 备案"   value={raw_intel.icp_record ?? '⚠️ 无备案'}   warn={!raw_intel.icp_record} />
            <IntelRow label="服务器"     value={`${raw_intel.server_country ?? '未知'} / ${raw_intel.server_isp ?? '—'}`} />
            <IntelRow label="SSL 证书"   value={raw_intel.ssl_valid ? (raw_intel.ssl_self_signed ? '⚠️ 自签名' : '有效') : '⚠️ 无效'} warn={!raw_intel.ssl_valid || raw_intel.ssl_self_signed} />
            <IntelRow label="WHOIS 隐私" value={raw_intel.whois_privacy ? '⚠️ 已隐藏' : '正常'} warn={raw_intel.whois_privacy} />
            <IntelRow label="黑名单"     value={raw_intel.blacklist_hit ? '⚠️ 命中' : '未命中'} warn={raw_intel.blacklist_hit} />
            <IntelRow label="投诉量"     value={`${raw_intel.complaint_count} 条`} />
          </div>
        </div>
      </div>

      {/* 风险特征热力图 */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
        <h2 className="text-slate-500 text-xs font-mono tracking-wider mb-4">风险特征热力图（XAI 可解释分析）</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-1">
          {(Object.entries({
            keyword_risk_score:      '风险话术密度',
            public_sentiment_neg:    '负面舆情强度',
            phishing_visual_sim:     '钓鱼视觉相似度',
            icp_missing:             'ICP 备案缺失',
            complaint_count_norm:    '投诉量',
            domain_age_days:         '域名注册时长',
            ip_overseas:             '境外服务器',
            ssl_self_signed:         'SSL 自签名',
            resource_load_anomaly:   '页面资源异常',
            whois_privacy_protected: 'WHOIS 信息隐藏',
            blacklist_hit:           '黑名单命中',
            ip_cdn_abuse:            'CDN 规避行为',
          }) as [keyof typeof features, string][]).map(([key, label]) => (
            <FeatureBar
              key={key}
              label={label}
              value={features[key] as number ?? 0}
              contrib={wras.feature_contrib[key] ?? 0}
            />
          ))}
        </div>
      </div>

    </div>
  )
}

// ── 情报行 ──────────────────────────────────────────────────────
function IntelRow({ label, value, warn = false }: { label: string; value: string; warn?: boolean }) {
  return (
    <div className="flex justify-between gap-4">
      <span className="text-slate-600 font-mono shrink-0">{label}</span>
      <span className={warn ? 'text-orange-400' : 'text-slate-300'} style={{ wordBreak: 'break-all', textAlign: 'right' }}>
        {value}
      </span>
    </div>
  )
}

// ── 特征进度条 ───────────────────────────────────────────────────
function FeatureBar({ label, value, contrib }: { label: string; value: number; contrib: number }) {
  const pct      = Math.round(value * 100)
  const barColor = value > 0.7 ? 'bg-red-500' : value > 0.4 ? 'bg-orange-500' : value > 0.2 ? 'bg-yellow-500' : 'bg-green-600'

  return (
    <div className="py-1.5">
      <div className="flex justify-between text-xs mb-1">
        <span className="text-slate-500 font-mono">{label}</span>
        <span className="text-slate-700">{pct}% · +{contrib.toFixed(2)}分</span>
      </div>
      <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
        <div
          className={`h-full ${barColor} rounded-full transition-all`}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  )
}
