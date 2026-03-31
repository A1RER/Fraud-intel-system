import type { RiskLevel, InputType } from './types'

// ── 风险等级样式 ────────────────────────────────────────────────
export const RISK_CONFIG: Record<string, {
  color: string; bg: string; border: string; emoji: string; label: string
}> = {
  HIGH:   { color: 'text-red-400',    bg: 'bg-red-950/50',    border: 'border-red-800',    emoji: '🔴', label: '高风险' },
  MEDIUM: { color: 'text-orange-400', bg: 'bg-orange-950/50', border: 'border-orange-800', emoji: '🟠', label: '中风险' },
  LOW:    { color: 'text-yellow-400', bg: 'bg-yellow-950/50', border: 'border-yellow-800', emoji: '🟡', label: '低风险' },
  SAFE:   { color: 'text-green-400',  bg: 'bg-green-950/50',  border: 'border-green-800',  emoji: '🟢', label: '暂无风险' },
}

// WRAS 风险等级（URL 分析详细报告）
export const WRAS_LEVEL_CONFIG: Record<RiskLevel, {
  color: string; bg: string; border: string; emoji: string; label: string
}> = {
  RED:    { color: 'text-red-400',    bg: 'bg-red-950/50',    border: 'border-red-800',    emoji: '🔴', label: '高危' },
  ORANGE: { color: 'text-orange-400', bg: 'bg-orange-950/50', border: 'border-orange-800', emoji: '🟠', label: '中高风险' },
  YELLOW: { color: 'text-yellow-400', bg: 'bg-yellow-950/50', border: 'border-yellow-800', emoji: '🟡', label: '疑似风险' },
  GREEN:  { color: 'text-green-400',  bg: 'bg-green-950/50',  border: 'border-green-800',  emoji: '🟢', label: '暂无风险' },
}

// ── 输入标签页配置 ──────────────────────────────────────────────
export const INPUT_TABS: { key: InputType; label: string; icon: string; placeholder: string }[] = [
  { key: 'recruitment', label: '招聘信息', icon: '📋', placeholder: '粘贴你看到的招聘信息，例如：\n"急招运营助理，月薪8000-15000，零基础可培训，入职前需缴纳680元材料费..."' },
  { key: 'chat',        label: '聊天记录', icon: '💬', placeholder: '粘贴与招聘方的聊天内容，例如：\n"你好，我是XX公司HR，我们有内部推荐名额，需要先交一笔服务费..."' },
  { key: 'company',     label: '公司查询', icon: '🏢', placeholder: '输入公司名称，如：深圳XX教育科技有限公司' },
  { key: 'url',         label: '网站链接', icon: '🔗', placeholder: '输入目标网址，如：suspicious-recruit.com' },
]
