import { useEffect, useState } from 'react'
import { NavLink, Outlet, Link, useLocation } from 'react-router-dom'
import { Activity, BarChart3, BrainCircuit, History, LayoutDashboard, Link2, Mail, Menu, Settings, ShieldCheck, X, Database, AlertTriangle } from 'lucide-react'
import { api } from '../services/api'

const NAV = [
  { to: '/app', end: true, label: 'Dashboard', icon: LayoutDashboard },
  { to: '/app/url', label: 'URL Scanner', icon: Link2 },
  { to: '/app/email', label: 'Email Scanner', icon: Mail },
  { to: '/app/explainability', label: 'Explainability', icon: BrainCircuit },
  { to: '/app/models', label: 'Model Performance', icon: BarChart3 },
  { to: '/app/history', label: 'Scan History', icon: History },
  { to: '/app/settings', label: 'Settings', icon: Settings },
]

export const Logo = () => (
  <Link to="/" className="flex items-center gap-2.5">
    <div className="h-9 w-9 rounded-lg bg-gradient-to-br from-brand to-brand-purple grid place-items-center"><ShieldCheck size={20} className="text-white" /></div>
    <div className="leading-tight"><div className="font-semibold text-white">PhishGuard <span className="text-brand-purple">XAI</span></div>
      <div className="text-[10px] text-slate-400 uppercase tracking-wider">Detect · Explain · Advise</div></div>
  </Link>
)

export default function Layout() {
  const [open, setOpen] = useState(false)
  const [health, setHealth] = useState(null)
  const [offline, setOffline] = useState(false)
  const loc = useLocation()
  useEffect(() => setOpen(false), [loc.pathname])
  useEffect(() => { api.health().then((h) => { setHealth(h); setOffline(false) }).catch(() => setOffline(true)) }, [loc.pathname])

  return (
    <div className="min-h-screen lg:flex">
      {open && <div className="fixed inset-0 bg-black/60 z-30 lg:hidden" onClick={() => setOpen(false)} />}
      <aside className={`fixed z-40 inset-y-0 left-0 w-64 bg-ink-950 border-r border-ink-600/60 p-4 flex flex-col transition-transform lg:translate-x-0 lg:sticky lg:top-0 lg:h-screen ${open ? 'translate-x-0' : '-translate-x-full'}`}>
        <div className="flex items-center justify-between mb-8"><Logo />
          <button className="lg:hidden text-slate-400" onClick={() => setOpen(false)} aria-label="Close menu"><X size={20} /></button></div>
        <nav className="space-y-1 flex-1">
          {NAV.map(({ to, label, icon: Icon, end }) => (
            <NavLink key={to} to={to} end={end} className={({ isActive }) => `flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm transition-colors ${isActive ? 'bg-brand/15 text-white border border-brand/30' : 'text-slate-400 hover:bg-ink-700 hover:text-white border border-transparent'}`}>
              <Icon size={18} /> {label}
            </NavLink>
          ))}
        </nav>
        <div className="text-[11px] text-slate-500 leading-relaxed border-t border-ink-600/60 pt-3">
          Static analysis only — submitted URLs are never opened or executed.
        </div>
      </aside>

      <div className="flex-1 min-w-0">
        <header className="sticky top-0 z-20 bg-ink-900/90 backdrop-blur border-b border-ink-600/60 px-4 lg:px-8 h-14 flex items-center gap-3">
          <button className="lg:hidden text-slate-300" onClick={() => setOpen(true)} aria-label="Open menu"><Menu size={22} /></button>
          <div className="flex-1" />
          {offline ? <span className="flex items-center gap-1.5 text-xs text-red-300"><Activity size={14} /> Backend offline</span> : health && (
            <>
              <span className={`hidden sm:flex items-center gap-1.5 text-xs ${health.demo_mode ? 'text-amber-300' : 'text-emerald-300'}`}>
                {health.demo_mode ? <AlertTriangle size={14} /> : <Activity size={14} />}{health.demo_mode ? 'DEMO MODE — model not trained' : 'Models loaded'}</span>
              <span className={`flex items-center gap-1.5 text-xs ${health.storage.persistent ? 'text-sky-300' : 'text-amber-300'}`}><Database size={14} />
                <span className="hidden md:inline">{health.storage.label}</span><span className="md:hidden">{health.storage.persistent ? 'MongoDB' : 'Local file'}</span></span>
            </>)}
        </header>
        <main className="p-4 lg:p-8 max-w-[1400px] mx-auto"><Outlet /></main>
      </div>
    </div>
  )
}
