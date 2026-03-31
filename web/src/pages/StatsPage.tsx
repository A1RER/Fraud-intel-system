import { useState, useEffect } from 'react'
import type { IntelStats } from '../types'
import { RISK_CONFIG } from '../constants'
import { StatCard } from '../components/common'

export default function StatsPage() {
  const [stats, setStats] = useState<IntelStats | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch('/api/intel/stats')
      .then(r => r.json())
      .then(setStats)
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <p className="text-slate-500 text-sm text-center py-16 animate-pulse">加载中...</p>
  if (!stats) return <p className="text-slate-600 text-sm text-center py-16">暂无数据</p>

  const maxPattern = Math.max(...stats.fraud_patterns.map(p => p.total_count), 1)

  return (
    <main className="max-w-5xl mx-auto px-6 py-8 space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="总分析记录" value={stats.total_records} />
        <StatCard label="高风险企业" value={stats.total_companies} />
        <StatCard label="高风险记录" value={stats.level_stats['HIGH'] ?? 0} color="text-red-400" />
        <StatCard label="中风险记录" value={stats.level_stats['MEDIUM'] ?? 0} color="text-orange-400" />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <h2 className="text-slate-500 text-xs font-mono tracking-wider mb-4">诈骗类型分布</h2>
          {stats.fraud_patterns.length === 0 && <p className="text-slate-600 text-sm">暂无数据</p>}
          <div className="space-y-3">
            {stats.fraud_patterns.map(p => (
              <div key={p.fraud_type}>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-slate-400">{p.fraud_type}</span>
                  <span className="text-slate-600">{p.total_count} 次（高危 {p.high_count}）</span>
                </div>
                <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                  <div className="h-full bg-red-500 rounded-full" style={{ width: `${(p.total_count / maxPattern) * 100}%` }} />
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <h2 className="text-slate-500 text-xs font-mono tracking-wider mb-4">高频涉诈企业 TOP 10</h2>
          {stats.top_companies.length === 0 && <p className="text-slate-600 text-sm">暂无数据</p>}
          <div className="space-y-2">
            {stats.top_companies.map((c, i) => {
              const cfg = RISK_CONFIG[c.risk_level] ?? RISK_CONFIG.SAFE
              return (
                <div key={i} className="flex items-center justify-between text-sm">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="text-slate-600 font-mono w-5 text-right shrink-0">{i + 1}</span>
                    <span className={`${cfg.color} truncate`}>{c.company_name}</span>
                  </div>
                  <span className="text-slate-600 text-xs shrink-0">{c.hit_count} 次</span>
                </div>
              )
            })}
          </div>
        </div>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
        <h2 className="text-slate-500 text-xs font-mono tracking-wider mb-4">近 7 天分析趋势</h2>
        {stats.trend_7d.length === 0 && <p className="text-slate-600 text-sm">暂无数据</p>}
        <div className="flex items-end gap-2 h-32">
          {stats.trend_7d.map(d => {
            const maxCount = Math.max(...stats.trend_7d.map(x => x.count), 1)
            const h = Math.max((d.count / maxCount) * 100, 4)
            const hh = d.high_count > 0 ? Math.max((d.high_count / maxCount) * 100, 2) : 0
            return (
              <div key={d.date} className="flex-1 flex flex-col items-center gap-1">
                <div className="w-full flex flex-col items-center justify-end" style={{ height: '100px' }}>
                  <div className="w-full max-w-8 bg-blue-600 rounded-t" style={{ height: `${h}%` }}>
                    {hh > 0 && <div className="w-full bg-red-500 rounded-t" style={{ height: `${(hh / h) * 100}%` }} />}
                  </div>
                </div>
                <span className="text-slate-700 text-[10px]">{d.date.slice(5)}</span>
                <span className="text-slate-600 text-[10px]">{d.count}</span>
              </div>
            )
          })}
        </div>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
        <h2 className="text-slate-500 text-xs font-mono tracking-wider mb-4">风险等级分布</h2>
        <div className="grid grid-cols-4 gap-4">
          {(['HIGH', 'MEDIUM', 'LOW', 'SAFE'] as const).map(level => {
            const cfg = RISK_CONFIG[level]
            const count = stats.level_stats[level] ?? 0
            return (
              <div key={level} className={`${cfg.bg} ${cfg.border} border rounded-lg p-4 text-center`}>
                <p className="text-2xl">{cfg.emoji}</p>
                <p className={`${cfg.color} text-2xl font-bold font-mono`}>{count}</p>
                <p className="text-slate-500 text-xs mt-1">{cfg.label}</p>
              </div>
            )
          })}
        </div>
      </div>
    </main>
  )
}
