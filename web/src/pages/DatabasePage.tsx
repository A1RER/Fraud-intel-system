import { useState, useEffect } from 'react'
import type { IntelRecord, RiskyCompany } from '../types'
import { RISK_CONFIG } from '../constants'

export default function DatabasePage() {
  const [tab, setTab]           = useState<'records' | 'companies'>('records')
  const [records, setRecords]   = useState<IntelRecord[]>([])
  const [companies, setCompanies] = useState<RiskyCompany[]>([])
  const [total, setTotal]       = useState(0)
  const [loading, setLoading]   = useState(false)
  const [search, setSearch]     = useState('')
  const [riskFilter, setRiskFilter] = useState('')

  useEffect(() => { fetchData() }, [tab, riskFilter])

  async function fetchData() {
    setLoading(true)
    try {
      const params = new URLSearchParams()
      if (riskFilter) params.set('risk_level', riskFilter)
      if (search) params.set(tab === 'records' ? 'company_name' : 'keyword', search)
      params.set('limit', '50')

      const url = tab === 'records'
        ? `/api/intel/records?${params}`
        : `/api/intel/companies?${params}`

      const res = await fetch(url)
      const data = await res.json()
      if (tab === 'records') {
        setRecords(data.records || [])
        setTotal(data.total || 0)
      } else {
        setCompanies(data.companies || [])
        setTotal(data.total || 0)
      }
    } catch { /* ignore */ }
    setLoading(false)
  }

  function handleSearch() { fetchData() }
  const riskCfg = (level: string) => RISK_CONFIG[level] ?? RISK_CONFIG.SAFE

  return (
    <main className="max-w-5xl mx-auto px-6 py-8 space-y-6">
      <div className="flex flex-col sm:flex-row gap-3 items-start sm:items-center justify-between">
        <div className="flex gap-1 bg-slate-900 rounded-lg p-1">
          <button onClick={() => setTab('records')}
            className={`px-4 py-2 rounded-md text-sm font-medium transition-all cursor-pointer ${tab === 'records' ? 'bg-blue-600 text-white' : 'text-slate-500 hover:text-slate-300'}`}>
            分析记录
          </button>
          <button onClick={() => setTab('companies')}
            className={`px-4 py-2 rounded-md text-sm font-medium transition-all cursor-pointer ${tab === 'companies' ? 'bg-blue-600 text-white' : 'text-slate-500 hover:text-slate-300'}`}>
            高风险企业
          </button>
        </div>
        <div className="flex gap-2">
          <select value={riskFilter} onChange={e => setRiskFilter(e.target.value)}
            className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-300">
            <option value="">全部等级</option>
            <option value="HIGH">高风险</option>
            <option value="MEDIUM">中风险</option>
            <option value="LOW">低风险</option>
            <option value="SAFE">安全</option>
          </select>
          <input type="text" value={search} onChange={e => setSearch(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleSearch()} placeholder="搜索..."
            className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-300 placeholder-slate-600 w-40" />
          <button onClick={handleSearch} className="bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-lg text-sm cursor-pointer">搜索</button>
        </div>
      </div>

      <p className="text-slate-600 text-xs">共 {total} 条记录</p>
      {loading && <p className="text-slate-500 text-sm text-center py-8 animate-pulse">加载中...</p>}

      {tab === 'records' && !loading && (
        <div className="space-y-3">
          {records.length === 0 && <p className="text-slate-600 text-sm text-center py-12">暂无记录，去「风险识别」页面分析后自动入库</p>}
          {records.map(r => {
            const cfg = riskCfg(r.risk_level)
            return (
              <div key={r.id} className={`${cfg.bg} ${cfg.border} border rounded-lg p-4`}>
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`${cfg.color} font-bold text-sm`}>{cfg.emoji} {cfg.label}</span>
                      <span className="text-slate-600 text-xs font-mono">{r.risk_score.toFixed(1)}分</span>
                      <span className="text-slate-700 text-xs">{r.input_type}</span>
                    </div>
                    <p className="text-slate-300 text-sm truncate">{r.summary}</p>
                    {r.company_name && <p className="text-slate-500 text-xs mt-1">企业：{r.company_name}</p>}
                    {r.fraud_types.length > 0 && (
                      <div className="flex gap-1 mt-2 flex-wrap">
                        {r.fraud_types.map((ft, i) => <span key={i} className="bg-red-950/50 text-red-300 border border-red-800/50 px-2 py-0.5 rounded text-xs">{ft}</span>)}
                      </div>
                    )}
                  </div>
                  <div className="text-right shrink-0">
                    <p className="text-slate-700 text-xs font-mono">{r.report_id}</p>
                    <p className="text-slate-700 text-xs">{r.created_at}</p>
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {tab === 'companies' && !loading && (
        <div className="space-y-3">
          {companies.length === 0 && <p className="text-slate-600 text-sm text-center py-12">暂无高风险企业记录</p>}
          {companies.map(c => {
            const cfg = riskCfg(c.risk_level)
            return (
              <div key={c.id} className={`${cfg.bg} ${cfg.border} border rounded-lg p-4`}>
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`${cfg.color} font-bold text-sm`}>{cfg.emoji} {c.company_name}</span>
                    </div>
                    <div className="flex items-center gap-3 text-xs text-slate-500">
                      <span>风险分 {c.risk_score.toFixed(1)}</span>
                      <span>被识别 {c.hit_count} 次</span>
                      <span>首次发现 {c.first_seen}</span>
                    </div>
                    {c.fraud_types.length > 0 && (
                      <div className="flex gap-1 mt-2 flex-wrap">
                        {c.fraud_types.map((ft, i) => <span key={i} className="bg-orange-950/50 text-orange-300 border border-orange-800/50 px-2 py-0.5 rounded text-xs">{ft}</span>)}
                      </div>
                    )}
                  </div>
                  <div className="text-right shrink-0 text-xs text-slate-700"><p>最近 {c.last_seen}</p></div>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </main>
  )
}
