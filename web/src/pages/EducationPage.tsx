import { useState, useEffect } from 'react'
import type { IntelStats } from '../types'
import { RISK_CONFIG } from '../constants'

// ── 典型案例库 ──────────────────────────────────────────────────
const CASES = [
  {
    type: '付费培训诈骗',
    title: '以"包就业"为名收取培训费',
    scenario: '某公司在社交平台发布"急招运营助理，月薪8000-15000，零基础可培训"，求职者联系后被告知需先缴纳680元材料费和3980元培训费，承诺"培训后包入职"。',
    redFlags: ['入职前收取任何费用', '"包就业""包分配"承诺', '培训费、材料费、建档费等名目'],
    tips: '正规公司不会在入职前收取任何费用。遇到类似情况请立即终止联系。',
  },
  {
    type: '虚假内推诈骗',
    title: '付费内推名企 offer',
    scenario: '某"求职中介"声称有大厂内部渠道，交19800元即可获得名企实习/正式 offer，"名额有限，先到先得"。付款后对方失联或提供的岗位根本不存在。',
    redFlags: ['付费内推', '"内部渠道""内部名额"', '保 offer、保录取', '制造紧迫感'],
    tips: '真正的内推不需要收费。请直接通过企业官网或正规招聘平台投递简历。',
  },
  {
    type: '高薪诱导诈骗',
    title: '兼职刷单日入 500+',
    scenario: '微信群里有人分享"在家兼职，动动手指日入500+"的信息。加入后先完成几笔小额任务并获得佣金回报，之后被要求投入更大金额，最终无法提现。',
    redFlags: ['"日赚""日入""轻松月入"', '不合理的高薪承诺', '需要先垫付资金', '私聊引导到非正规平台'],
    tips: '天下没有免费的午餐。任何要求先投入资金才能获得回报的"兼职"都是诈骗。',
  },
  {
    type: '信息盗取诈骗',
    title: '以入职为名骗取个人信息',
    scenario: '求职者收到"录用通知"，被要求提供身份证正反面照片、银行卡信息、手机验证码等，声称用于"入职登记"和"薪资发放"。这些信息随后被用于网贷申请或电信诈骗。',
    redFlags: ['要求提供验证码', '手持身份证照片', '银行卡完整信息', '尚未签订合同就要求提供敏感信息'],
    tips: '正规入职仅需身份证复印件，绝不会索要验证码、银行卡密码等信息。',
  },
]

// ── 防范口诀 ────────────────────────────────────────────────────
const RULES = [
  { icon: '🚫', title: '不交钱', desc: '入职前以任何名目收费的都是诈骗' },
  { icon: '🔍', title: '先核实', desc: '在企查查/天眼查核实公司信息，在正规平台查看岗位' },
  { icon: '🛡️', title: '护信息', desc: '不向未签约公司提供身份证照片、银行卡、验证码' },
  { icon: '⚠️', title: '警高薪', desc: '远超行业水平的薪资承诺大概率是诈骗诱饵' },
  { icon: '📞', title: '会求助', desc: '遇到可疑招聘可拨打 12321 举报或使用本系统检测' },
]


export default function EducationPage() {
  const [stats, setStats] = useState<IntelStats | null>(null)

  useEffect(() => {
    fetch('/api/intel/stats')
      .then(r => r.json())
      .then(setStats)
      .catch(() => {})
  }, [])

  return (
    <main className="max-w-5xl mx-auto px-6 py-8 space-y-8">

      {/* 标题 */}
      <div className="text-center">
        <h2 className="text-xl font-bold text-blue-400">反诈宣教中心</h2>
        <p className="text-slate-500 text-sm mt-2">了解常见招聘诈骗手法，提高防范意识</p>
      </div>

      {/* 防范口诀 */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
        <h3 className="text-slate-400 text-xs font-mono tracking-wider mb-4">求职防诈五字诀</h3>
        <div className="grid grid-cols-1 sm:grid-cols-5 gap-4">
          {RULES.map(r => (
            <div key={r.title} className="text-center">
              <div className="text-3xl mb-2">{r.icon}</div>
              <p className="text-blue-400 font-bold text-sm">{r.title}</p>
              <p className="text-slate-500 text-xs mt-1">{r.desc}</p>
            </div>
          ))}
        </div>
      </div>

      {/* 高发预警（基于系统数据） */}
      {stats && stats.fraud_patterns.length > 0 && (
        <div className="bg-red-950/30 border border-red-900 rounded-xl p-6">
          <h3 className="text-red-400 text-xs font-mono tracking-wider mb-4">当前高发诈骗类型预警</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4">
            {stats.fraud_patterns.slice(0, 6).map(p => {
              const cfg = RISK_CONFIG[p.high_count > 0 ? 'HIGH' : 'MEDIUM']
              return (
                <div key={p.fraud_type} className="bg-slate-950/50 rounded-lg p-4 border border-slate-800">
                  <p className={`${cfg.color} font-bold text-sm`}>{cfg.emoji} {p.fraud_type}</p>
                  <div className="flex items-center gap-3 mt-2 text-xs text-slate-500">
                    <span>累计 {p.total_count} 次</span>
                    {p.high_count > 0 && <span className="text-red-400">高危 {p.high_count} 次</span>}
                  </div>
                  {p.recent_keywords.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-2">
                      {p.recent_keywords.slice(0, 5).map((kw, i) => (
                        <span key={i} className="bg-slate-900 text-slate-500 px-1.5 py-0.5 rounded text-[10px]">{kw}</span>
                      ))}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* 典型案例 */}
      <div>
        <h3 className="text-slate-400 text-xs font-mono tracking-wider mb-4">典型案例详解</h3>
        <div className="space-y-4">
          {CASES.map((c, idx) => (
            <CaseCard key={idx} {...c} />
          ))}
        </div>
      </div>

      {/* 举报渠道 */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
        <h3 className="text-slate-400 text-xs font-mono tracking-wider mb-4">举报与求助渠道</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
          <div className="bg-slate-950 rounded-lg p-4 border border-slate-800">
            <p className="text-blue-400 font-bold">12321</p>
            <p className="text-slate-500 text-xs mt-1">网络不良信息举报热线</p>
          </div>
          <div className="bg-slate-950 rounded-lg p-4 border border-slate-800">
            <p className="text-blue-400 font-bold">110</p>
            <p className="text-slate-500 text-xs mt-1">遭遇诈骗请立即报警</p>
          </div>
          <div className="bg-slate-950 rounded-lg p-4 border border-slate-800">
            <p className="text-blue-400 font-bold">12315</p>
            <p className="text-slate-500 text-xs mt-1">消费者投诉举报热线</p>
          </div>
        </div>
      </div>
    </main>
  )
}


function CaseCard({ type, title, scenario, redFlags, tips }: {
  type: string; title: string; scenario: string; redFlags: string[]; tips: string
}) {
  const [open, setOpen] = useState(false)

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
      <button onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between p-5 text-left cursor-pointer hover:bg-slate-800/30 transition-colors">
        <div className="flex items-center gap-3">
          <span className="bg-red-950 text-red-300 border border-red-800 px-2.5 py-0.5 rounded-full text-xs">{type}</span>
          <span className="text-slate-300 text-sm font-medium">{title}</span>
        </div>
        <span className="text-slate-600 text-sm">{open ? '▲' : '▼'}</span>
      </button>
      {open && (
        <div className="px-5 pb-5 space-y-3 border-t border-slate-800 pt-4">
          <div>
            <p className="text-slate-500 text-xs font-mono mb-1">案例场景</p>
            <p className="text-slate-400 text-sm leading-relaxed">{scenario}</p>
          </div>
          <div>
            <p className="text-slate-500 text-xs font-mono mb-1">危险信号</p>
            <ul className="space-y-1">
              {redFlags.map((f, i) => <li key={i} className="text-red-400 text-sm">⚠️ {f}</li>)}
            </ul>
          </div>
          <div className="bg-blue-950/30 border border-blue-900 rounded-lg p-3">
            <p className="text-blue-400 text-sm">💡 {tips}</p>
          </div>
        </div>
      )}
    </div>
  )
}
