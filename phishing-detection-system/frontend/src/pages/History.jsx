import { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { ArrowLeft, BrainCircuit, Eye, Trash2 } from 'lucide-react'
import { Alert, Card, ClassBadge, Empty, PageHeader, Spinner } from '../components/ui'
import ResultView from '../components/ResultView'
import { useAsync } from '../hooks/useAsync'
import { api, errorMessage } from '../services/api'
import { fmtDate } from '../lib'

const FILTERS = [['', 'All'], ['SAFE', 'Safe'], ['SUSPICIOUS', 'Suspicious'], ['PHISHING', 'Phishing']]

export function HistoryPage() {
  const [filter, setFilter] = useState('')
  const [msg, setMsg] = useState(null)
  const { data, loading, error, reload } = useAsync(() => api.history({ classification: filter || undefined, limit: 200 }), [filter])
  const del = async (id) => { try { await api.deleteScan(id); setMsg({ kind: 'success', t: 'Scan deleted.' }); reload() } catch (e) { setMsg({ kind: 'error', t: errorMessage(e) }) } }
  const clear = async () => {
    if (!window.confirm('Delete ALL scan history? This cannot be undone.')) return
    try { const r = await api.clearHistory(); setMsg({ kind: 'success', t: `Deleted ${r.deleted_count} scan(s).` }); reload() } catch (e) { setMsg({ kind: 'error', t: errorMessage(e) }) }
  }
  return (
    <div>
      <PageHeader title="Scan History" subtitle="Previous analyses. Message bodies and URL query strings are not stored unless full-input retention is enabled by the administrator.">
        <button className="btn-danger" onClick={clear} disabled={!data?.total}><Trash2 size={15} /> Clear all history</button></PageHeader>
      {data && !data.storage.persistent && <Alert kind="warning" className="mb-4" title="Local file mode">History is stored in a local JSON file (development fallback), not MongoDB.</Alert>}
      {msg && <Alert kind={msg.kind} className="mb-4">{msg.t}</Alert>}
      <div className="flex gap-2 mb-4 flex-wrap">{FILTERS.map(([v, l]) => <button key={l} onClick={() => setFilter(v)} className={`btn !py-1.5 border ${filter === v ? 'bg-brand/20 border-brand/50 text-white' : 'bg-ink-800 border-ink-600 text-slate-400 hover:text-white'}`}>{l}</button>)}</div>
      {error && <Alert kind="error">{error}</Alert>}
      <Card>
        {loading ? <Spinner /> : !data?.items.length ? <Empty>No scans found{filter ? ` with classification ${filter}` : ''}.</Empty> :
          <div className="overflow-x-auto"><table className="w-full text-sm"><thead><tr className="text-left text-xs text-slate-500 border-b border-ink-600/60"><th className="p-3">Type</th><th>Submitted</th><th>Classification</th><th>Risk</th><th>Date &amp; time</th><th className="text-right pr-3">Actions</th></tr></thead>
            <tbody>{data.items.map((r) => <tr key={r.scan_id} className="border-b border-ink-700/60 hover:bg-ink-700/30"><td className="p-3 capitalize">{r.input_type}</td><td className="max-w-[340px] truncate font-mono text-xs" title={r.input_summary}>{r.input_summary}</td>
              <td><ClassBadge value={r.classification} /></td><td>{Math.round(r.risk_score)}</td><td className="text-xs text-slate-400 whitespace-nowrap">{fmtDate(r.created_at)}</td>
              <td className="text-right pr-3 whitespace-nowrap"><Link to={`/app/history/${r.scan_id}`} className="btn-ghost !py-1 !px-2 mr-1"><Eye size={14} /> View details</Link>
                <button className="btn-danger !py-1 !px-2" onClick={() => del(r.scan_id)} aria-label="Delete scan"><Trash2 size={14} /></button></td></tr>)}</tbody></table></div>}
      </Card>
      {data && <p className="text-xs text-slate-500 mt-2">{data.total} record(s)</p>}
    </div>
  )
}

export function HistoryDetail() {
  const { id } = useParams()
  const nav = useNavigate()
  const { data, loading, error } = useAsync(() => api.historyItem(id), [id])
  return (
    <div>
      <button className="btn-ghost mb-4" onClick={() => nav('/app/history')}><ArrowLeft size={15} /> Back to history</button>
      {loading && <Spinner />}{error && <Alert kind="error">{error}</Alert>}
      {data && <>
        <PageHeader title="Scan details" subtitle={`Recorded ${fmtDate(data.created_at)}`}><Link className="btn-ghost" to={`/app/explainability?scan=${id}`}><BrainCircuit size={15} /> Open in Explainability</Link></PageHeader>
        <ResultView result={data.result} /></>}
    </div>
  )
}
