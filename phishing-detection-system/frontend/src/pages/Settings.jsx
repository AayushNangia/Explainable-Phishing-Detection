import { Database, ExternalLink, Lock, Cpu } from 'lucide-react'
import { Alert, Card, PageHeader, Spinner } from '../components/ui'
import { useAsync } from '../hooks/useAsync'
import { api } from '../services/api'

const Row = ({ k, v }) => <div className="flex justify-between gap-4 py-2 border-b border-ink-700/60 text-sm"><span className="text-slate-400">{k}</span><span className="text-slate-100 text-right break-all">{v}</span></div>

export default function Settings() {
  const { data: s, loading, error } = useAsync(api.settings)
  const base = import.meta.env.VITE_API_URL || 'http://localhost:8000'
  return (
    <div>
      <PageHeader title="Settings" subtitle="Read-only view of the running configuration. Change values in the backend .env file and restart the API." />
      {loading && <Spinner />}{error && <Alert kind="error">{error}</Alert>}
      {s && <div className="grid lg:grid-cols-2 gap-4">
        <Card className="p-5"><div className="label mb-2 flex items-center gap-1.5"><Database size={14} /> Storage</div>
          <Row k="Active backend" v={s.storage.label} /><Row k="Persistent" v={s.storage.persistent ? 'Yes' : 'No (development fallback)'} />
          {!s.storage.persistent && <Alert kind="warning" className="mt-3">MongoDB is not connected. Set MONGODB_URI in .env and start MongoDB for persistent storage.</Alert>}</Card>
        <Card className="p-5"><div className="label mb-2 flex items-center gap-1.5"><Lock size={14} /> Privacy</div>
          <Row k="Retain full input (STORE_FULL_INPUT)" v={s.store_full_input ? 'ENABLED — raw URLs/message bodies are stored' : 'Disabled (recommended)'} />
          <Row k="Stored per scan" v="classification, score, findings, explanation, masked input summary" /><Row k="Never stored" v="passwords, OTPs, tokens, URL query strings, message bodies" /></Card>
        <Card className="p-5"><div className="label mb-2 flex items-center gap-1.5"><Cpu size={14} /> Models</div>
          {['url', 'email'].map((t) => { const m = s.models[t]; return <div key={t}><Row k={`${t.toUpperCase()} model`} v={m.trained ? `${m.model_name} (trained ${new Date(m.trained_at).toLocaleDateString()})` : 'NOT TRAINED'} />
            {m.hybrid && <Row k={`${t.toUpperCase()} hybrid α / thresholds`} v={`α=${m.hybrid.alpha}, safe<${m.hybrid.t_safe}, phishing≥${m.hybrid.t_phish}`} />}</div> })}</Card>
        <Card className="p-5"><div className="label mb-2">API &amp; limits</div><Row k="API base URL" v={base} /><Row k="Allowed frontend origin (CORS)" v={s.frontend_origin} /><Row k="Max URL length" v={s.max_url_length} /><Row k="Max message length" v={`${s.max_email_chars} chars`} />
          <a className="btn-ghost mt-3" href={`${base}/docs`} target="_blank" rel="noreferrer"><ExternalLink size={14} /> Open interactive API docs</a></Card>
      </div>}
    </div>
  )
}
