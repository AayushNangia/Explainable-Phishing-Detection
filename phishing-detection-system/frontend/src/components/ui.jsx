import { useState } from 'react'
import { AlertTriangle, CheckCircle2, ChevronDown, Info, Loader2, XCircle } from 'lucide-react'
import { CLASS_STYLES } from '../lib'

export const Card = ({ className = '', children }) => <div className={`card ${className}`}>{children}</div>

export function PageHeader({ title, subtitle, children }) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-3 mb-6">
      <div>
        <h1 className="text-2xl font-semibold text-white">{title}</h1>
        {subtitle && <p className="text-sm text-slate-400 mt-1 max-w-2xl">{subtitle}</p>}
      </div>
      {children}
    </div>
  )
}

export const Spinner = ({ label = 'Loading…' }) => (
  <div className="flex items-center gap-2 text-slate-400 text-sm py-8 justify-center">
    <Loader2 className="animate-spin" size={18} /> {label}
  </div>
)

const ALERTS = {
  error: { icon: XCircle, cls: 'border-red-500/40 bg-red-500/10 text-red-200' },
  warning: { icon: AlertTriangle, cls: 'border-amber-500/40 bg-amber-500/10 text-amber-200' },
  success: { icon: CheckCircle2, cls: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200' },
  info: { icon: Info, cls: 'border-sky-500/40 bg-sky-500/10 text-sky-200' },
}
export function Alert({ kind = 'info', title, children, className = '' }) {
  const { icon: Icon, cls } = ALERTS[kind]
  return (
    <div role="alert" className={`flex gap-3 rounded-lg border px-4 py-3 text-sm ${cls} ${className}`}>
      <Icon size={18} className="shrink-0 mt-0.5" />
      <div>{title && <div className="font-medium">{title}</div>}<div className="opacity-90">{children}</div></div>
    </div>
  )
}

export function ClassBadge({ value, size = 'sm' }) {
  const s = CLASS_STYLES[value] || CLASS_STYLES.SAFE
  const pad = size === 'lg' ? 'px-4 py-1.5 text-base' : 'px-2.5 py-0.5 text-xs'
  return <span className={`inline-block rounded-full border font-semibold tracking-wide ${pad} ${s.bg} ${s.border} ${s.text}`}>{value}</span>
}

export function StatCard({ icon: Icon, label, value, tone = 'brand', hint }) {
  const tones = { brand: 'text-blue-300 bg-blue-500/10', safe: 'text-emerald-300 bg-emerald-500/10', warn: 'text-amber-300 bg-amber-500/10', danger: 'text-red-300 bg-red-500/10', purple: 'text-violet-300 bg-violet-500/10' }
  return (
    <Card className="p-4 flex items-center gap-4">
      <div className={`h-11 w-11 rounded-lg grid place-items-center ${tones[tone]}`}><Icon size={20} /></div>
      <div><div className="text-2xl font-semibold text-white leading-none">{value}</div>
        <div className="text-xs text-slate-400 mt-1">{label}</div>{hint && <div className="text-[11px] text-slate-500">{hint}</div>}</div>
    </Card>
  )
}

export function Collapsible({ title, icon: Icon, defaultOpen = true, right, children }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <Card>
      <button onClick={() => setOpen(!open)} className="w-full flex items-center gap-2 px-4 py-3 text-left" aria-expanded={open}>
        {Icon && <Icon size={17} className="text-brand" />}
        <span className="font-medium text-white flex-1">{title}</span>
        {right}
        <ChevronDown size={17} className={`text-slate-400 transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>
      {open && <div className="px-4 pb-4 border-t border-ink-600/60 pt-4">{children}</div>}
    </Card>
  )
}

export const Empty = ({ children }) => <div className="text-sm text-slate-500 py-6 text-center">{children}</div>
