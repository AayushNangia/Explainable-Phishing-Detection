export const CLASS_STYLES = {
  SAFE: { text: 'text-emerald-300', bg: 'bg-emerald-500/10', border: 'border-emerald-500/40', hex: '#10b981', label: 'SAFE' },
  SUSPICIOUS: { text: 'text-amber-300', bg: 'bg-amber-500/10', border: 'border-amber-500/40', hex: '#f59e0b', label: 'SUSPICIOUS' },
  PHISHING: { text: 'text-red-300', bg: 'bg-red-500/10', border: 'border-red-500/40', hex: '#ef4444', label: 'PHISHING' },
}
export const SEVERITY_STYLES = {
  high: 'bg-red-500/15 text-red-300 border-red-500/30',
  medium: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
  low: 'bg-sky-500/15 text-sky-300 border-sky-500/30',
}
export const pct = (v, d = 1) => (v == null ? '—' : `${(v * 100).toFixed(d)}%`)
export const fmtDate = (iso) => new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
