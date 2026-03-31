import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom'
import AnalyzePage from './pages/AnalyzePage'
import DatabasePage from './pages/DatabasePage'
import StatsPage from './pages/StatsPage'
import EducationPage from './pages/EducationPage'

const NAV_ITEMS = [
  { to: '/',          label: '风险识别', icon: '🔍' },
  { to: '/database',  label: '情报库',   icon: '🗄️' },
  { to: '/stats',     label: '数据看板', icon: '📊' },
  { to: '/education', label: '反诈宣教', icon: '📚' },
]

export default function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-slate-950 text-slate-300">
        {/* 顶部导航 */}
        <header className="border-b border-slate-800 px-6 py-4">
          <div className="max-w-5xl mx-auto flex items-center justify-between">
            <NavLink to="/" className="flex items-center gap-3 no-underline">
              <span className="text-2xl">👁️</span>
              <div>
                <h1 className="text-blue-400 font-bold tracking-widest text-sm">
                  慧眼 · 招聘诈骗识别与预警系统
                </h1>
                <p className="text-slate-600 text-xs font-mono">
                  WISE EYE — AI-Powered Recruitment Fraud Detection
                </p>
              </div>
            </NavLink>

            <nav className="flex gap-1 bg-slate-900 rounded-lg p-1">
              {NAV_ITEMS.map(nav => (
                <NavLink
                  key={nav.to}
                  to={nav.to}
                  end={nav.to === '/'}
                  className={({ isActive }) =>
                    `flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-all no-underline
                    ${isActive ? 'bg-blue-600 text-white' : 'text-slate-500 hover:text-slate-300'}`
                  }
                >
                  <span>{nav.icon}</span>
                  <span>{nav.label}</span>
                </NavLink>
              ))}
            </nav>
          </div>
        </header>

        {/* 路由 */}
        <Routes>
          <Route path="/" element={<AnalyzePage />} />
          <Route path="/database" element={<DatabasePage />} />
          <Route path="/stats" element={<StatsPage />} />
          <Route path="/education" element={<EducationPage />} />
        </Routes>
      </div>
    </BrowserRouter>
  )
}
