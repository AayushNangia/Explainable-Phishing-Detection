import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip, Legend, BarChart, Bar, XAxis, YAxis, CartesianGrid } from 'recharts'
import { AlertTriangle, CheckCircle2, Link2, Mail, ShieldAlert, Activity } from 'lucide-react'
import { Alert, Card, ClassBadge, Empty, PageHeader, Spinner, StatCard } from '../components/ui'
import { tipStyle } from '../components/charts'
import { EmailScanForm, UrlScanForm } from '../components/ScanForms'
import { useAsync } from '../hooks/useAsync'
import { api } from '../services/api'
import { CLASS_STYLES, fmtDate } from '../lib'

function QuickResult({ r, to }) {
  if (!r) return null
  const s = CLASS_STYLES[r.classification]
  return (
    <div className={`mt-3 rounded-lg border p-3 flex items-center gap-3 ${s.bg} ${s.border}`}>
      <ClassBadge value={r.classification} /><span className="text-sm text-white">Risk {Math.round(r.risk_score)}/100</span>
      <Link to={to} className="ml-auto text-xs text-brand hover:underline">Full report →</Link>
    </div>
  )
}

export default function Dashboard() {
  const { data: s, loading, error, reload } = useAsync(api.stats)
  const [qu, setQu] = useState(null)
  const [qe, setQe] = useState(null)
  return (
    <div>
      <PageHeader title="Dashboard" subtitle="Live statistics calculated from stored scan records." />
      {error && <Alert kind="error" title="Could not load dashboard">{error}</Alert>}
      {loading && !s && <Spinner />}
      {s && (
        <>
          {!s.storage.persistent && <Alert kind="warning" className="mb-4" title="Local file mode">Scans are saved to a local JSON file for development, not MongoDB. See the README to enable MongoDB.</Alert>}
          <div className="grid grid-cols-2 lg:grid-cols-5 gap-3 mb-6">
            <StatCard icon={Link2} label="URLs analysed" value={s.total_urls} tone="brand" />
            <StatCard icon={CheckCircle2} label="Safe URLs" value={s.safe_urls} tone="safe" />
            <StatCard icon={AlertTriangle} label="Suspicious URLs" value={s.suspicious_urls} tone="warn" />
            <StatCard icon={ShieldAlert} label="Phishing URLs" value={s.phishing_urls} tone="danger" />
            <StatCard icon={Mail} label="Email analyses" value={s.total_emails} tone="purple" />
          </div>
          <div className="grid lg:grid-cols-3 gap-4 mb-6">
            <Card className="p-5"><div className="label mb-3">Risk distribution (all scans)</div>
              {s.risk_distribution.every((d) => d.value === 0) ? <Empty>No scans yet. Run a scan below.</Empty> :
                <div style={{ height: 230 }}><ResponsiveContainer><PieChart><Pie data={s.risk_distribution} dataKey="value" nameKey="name" innerRadius={55} outerRadius={85} paddingAngle={2} stroke="none">
                  {s.risk_distribution.map((d) => <Cell key={d.name} fill={CLASS_STYLES[d.name].hex} />)}</Pie><Tooltip contentStyle={tipStyle} /><Legend /></PieChart></ResponsiveContainer></div>}
            </Card>
            <Card className="p-5 lg:col-span-2"><div className="label mb-3 flex items-center gap-1.5"><Activity size={14} /> Detection activity (last 14 days)</div>
              {s.activity.every((d) => d.SAFE + d.SUSPICIOUS + d.PHISHING === 0) ? <Empty>No activity in the last 14 days.</Empty> :
                <div style={{ height: 230 }}><ResponsiveContainer><BarChart data={s.activity.map((d) => ({ ...d, date: d.date.slice(5) }))}><CartesianGrid stroke="#22304f" vertical={false} />
                  <XAxis dataKey="date" stroke="#64748b" tick={{ fontSize: 11 }} /><YAxis allowDecimals={false} stroke="#64748b" tick={{ fontSize: 11 }} /><Tooltip contentStyle={tipStyle} cursor={{ fill: '#ffffff08' }} /><Legend />
                  <Bar dataKey="SAFE" stackId="a" fill="#10b981" /><Bar dataKey="SUSPICIOUS" stackId="a" fill="#f59e0b" /><Bar dataKey="PHISHING" stackId="a" fill="#ef4444" /></BarChart></ResponsiveContainer></div>}
            </Card>
          </div>
        </>
      )}
      <div className="grid lg:grid-cols-2 gap-4 mb-6">
        <Card className="p-5"><div className="label mb-3 flex items-center gap-1.5"><Link2 size={14} /> Quick URL scanner</div><UrlScanForm compact onResult={(r) => { setQu(r); reload() }} /><QuickResult r={qu} to="/app/url" /></Card>
        <Card className="p-5"><div className="label mb-3 flex items-center gap-1.5"><Mail size={14} /> Quick email scanner</div><EmailScanForm compact onResult={(r) => { setQe(r); reload() }} /><QuickResult r={qe} to="/app/email" /></Card>
      </div>
      {s && (
        <Card className="p-5"><div className="flex items-center mb-3"><div className="label">Recent scan history</div><Link to="/app/history" className="ml-auto text-xs text-brand hover:underline">View all</Link></div>
          {s.recent.length === 0 ? <Empty>No scans recorded yet.</Empty> :
            <div className="overflow-x-auto"><table className="w-full text-sm"><thead><tr className="text-left text-xs text-slate-500 border-b border-ink-600/60"><th className="py-2">Type</th><th>Input</th><th>Result</th><th>Risk</th><th>When</th></tr></thead>
              <tbody>{s.recent.map((r) => <tr key={r.scan_id} className="border-b border-ink-700/60"><td className="py-2 capitalize">{r.input_type}</td><td className="max-w-[320px] truncate font-mono text-xs">{r.input_summary}</td><td><ClassBadge value={r.classification} /></td><td>{Math.round(r.risk_score)}</td><td className="text-slate-400 text-xs">{fmtDate(r.created_at)}</td></tr>)}</tbody></table></div>}
        </Card>)}
    </div>
  )
}
