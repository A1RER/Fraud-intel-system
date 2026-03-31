// 通用小组件

export function IntelRow({ label, value, warn = false }: { label: string; value: string; warn?: boolean }) {
  return (
    <div className="flex justify-between gap-4">
      <span className="text-slate-600 font-mono shrink-0">{label}</span>
      <span className={warn ? 'text-orange-400' : 'text-slate-300'} style={{ wordBreak: 'break-all', textAlign: 'right' }}>
        {value}
      </span>
    </div>
  )
}

export function FeatureBar({ label, value, contrib }: { label: string; value: number; contrib: number }) {
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

export function StatCard({ label, value, color = 'text-blue-400' }: { label: string; value: number; color?: string }) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 text-center">
      <p className={`${color} text-3xl font-bold font-mono`}>{value}</p>
      <p className="text-slate-500 text-xs mt-1">{label}</p>
    </div>
  )
}
