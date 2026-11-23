import { Bar, BarChart, Cell, CartesianGrid, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { CLASS_STYLES } from '../lib'

const tipStyle = { background: '#0b1220', border: '1px solid #2d3d62', borderRadius: 8, fontSize: 12, color: '#e2e8f0' }

/** Signed horizontal bar chart: positive (raises phishing risk) = red, negative = green. */
export function ContributionChart({ items, valueKey, labelKey = 'feature', unit }) {
  if (!items?.length) return null
  const data = [...items].sort((a, b) => Math.abs(b[valueKey]) - Math.abs(a[valueKey])).map((d) => ({ ...d, label: String(d[labelKey]).slice(0, 34), v: Number(d[valueKey].toFixed(4)) }))
  return (
    <div style={{ height: Math.max(180, data.length * 30 + 40) }} role="img" aria-label="Feature contribution chart">
      <ResponsiveContainer>
        <BarChart data={data} layout="vertical" margin={{ left: 8, right: 24, top: 4, bottom: 4 }}>
          <CartesianGrid stroke="#22304f" horizontal={false} />
          <XAxis type="number" stroke="#64748b" tick={{ fontSize: 11 }} label={unit ? { value: unit, position: 'insideBottom', offset: -2, fill: '#64748b', fontSize: 11 } : undefined} />
          <YAxis type="category" dataKey="label" width={170} stroke="#94a3b8" tick={{ fontSize: 11 }} />
          <ReferenceLine x={0} stroke="#64748b" />
          <Tooltip contentStyle={tipStyle} cursor={{ fill: '#ffffff08' }}
            formatter={(v, _n, p) => [`${v > 0 ? '+' : ''}${v}`, p.payload.direction]} />
          <Bar dataKey="v" radius={3}>
            {data.map((d, i) => <Cell key={i} fill={d.v >= 0 ? '#ef4444' : '#10b981'} />)}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}

/** Horizontal risk bar showing the tuned SAFE / SUSPICIOUS / PHISHING thresholds. */
export function RiskBar({ score, tSafe, tPhish, classification }) {
  const s = CLASS_STYLES[classification]
  const a = tSafe * 100, b = tPhish * 100
  return (
    <div>
      <div className="relative h-3 rounded-full overflow-hidden flex bg-ink-700">
        <div style={{ width: `${a}%` }} className="bg-emerald-500/50" />
        <div style={{ width: `${b - a}%` }} className="bg-amber-500/50" />
        <div style={{ width: `${100 - b}%` }} className="bg-red-500/50" />
        <div className="absolute top-0 bottom-0 w-1 bg-white rounded" style={{ left: `calc(${Math.min(score, 99.5)}% - 2px)` }} />
      </div>
      <div className="relative h-4 mt-1 text-[10px] text-slate-500">
        <span className="absolute" style={{ left: 0 }}>0</span>
        <span className="absolute -translate-x-1/2" style={{ left: `${a}%` }}>{a.toFixed(0)}</span>
        <span className="absolute -translate-x-1/2" style={{ left: `${b}%` }}>{b.toFixed(0)}</span>
        <span className="absolute right-0">100</span>
      </div>
      <div className="text-[11px] text-slate-500 mt-1">Thresholds: SAFE &lt; {a.toFixed(1)} ≤ SUSPICIOUS &lt; {b.toFixed(1)} ≤ PHISHING</div>
    </div>
  )
}

export { tipStyle }
