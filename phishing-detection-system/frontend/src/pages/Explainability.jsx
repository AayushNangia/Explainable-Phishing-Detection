import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { BrainCircuit, Microscope } from 'lucide-react'
import { Alert, Card, ClassBadge, Collapsible, Empty, PageHeader, Spinner } from '../components/ui'
import { ExplainerPanel } from '../components/ResultView'
import { useLatestResult } from '../hooks/ResultContext'
import { api, errorMessage } from '../services/api'
import { fmtDate } from '../lib'

export default function Explainability() {
  const { latest } = useLatestResult()
  const [params, setParams] = useSearchParams()
  const [history, setHistory] = useState([])
  const [selected, setSelected] = useState(params.get('scan') || (latest ? 'latest' : ''))
  const [record, setRecord] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  useEffect(() => { api.history({ limit: 50 }).then((h) => setHistory(h.items)).catch(() => {}) }, [latest])
  useEffect(() => {
    if (!selected || selected === 'latest') { setRecord(null); return }
    setLoading(true); setError(null)
    api.historyItem(selected).then((r) => setRecord(r.result)).catch((e) => setError(errorMessage(e))).finally(() => setLoading(false))
  }, [selected])

  const res = selected === 'latest' ? latest : record
  const choose = (v) => { setSelected(v); if (v && v !== 'latest') setParams({ scan: v }); else setParams({}) }

  return (
    <div>
      <PageHeader title="Explainability" subtitle="SHAP and LIME explanations computed from the trained model and the actual input. Nothing on this page is pre-written or simulated." />
      <Card className="p-4 mb-6">
        <label className="label">Choose an analysis to explain</label>
        <select value={selected} onChange={(e) => choose(e.target.value)} className="mt-1">
          <option value="">— select —</option>
          {latest && <option value="latest">Latest analysis: {latest.input_summary.slice(0, 60)}</option>}
          {history.map((h) => <option key={h.scan_id} value={h.scan_id}>[{h.input_type}] {h.input_summary.slice(0, 55)} — {h.classification} ({fmtDate(h.created_at)})</option>)}
        </select>
      </Card>
      {error && <Alert kind="error">{error}</Alert>}
      {loading && <Spinner />}
      {!res && !loading && <Card><Empty>No analysis selected. Run a scan in the <Link className="text-brand" to="/app/url">URL</Link> or <Link className="text-brand" to="/app/email">Email</Link> scanner, then return here.</Empty></Card>}
      {res && (
        <div className="space-y-4">
          <Card className="p-4 flex flex-wrap items-center gap-3"><ClassBadge value={res.classification} /><span className="text-white font-medium">Risk {Math.round(res.risk_score)}/100</span>
            <span className="text-slate-400 text-sm">ML probability: {res.ml.available ? `${(res.ml.probability * 100).toFixed(1)}% (${res.ml.model_name})` : 'N/A — model not trained'}</span>
            <span className="text-xs text-slate-500 font-mono truncate max-w-full">{res.input_summary}</span></Card>
          <div className="grid xl:grid-cols-2 gap-4 items-start">
            <Collapsible title="SHAP — feature contributions" icon={BrainCircuit}>
              <p className="text-xs text-slate-400 mb-3">SHAP assigns every feature a contribution to this prediction, based on Shapley values from game theory. Red bars increased the phishing risk; green bars decreased it.</p>
              <ExplainerPanel res={res.explanations.shap} kind="SHAP" /></Collapsible>
            <Collapsible title="LIME — local explanation" icon={Microscope}>
              <p className="text-xs text-slate-400 mb-3">LIME perturbs this input many times, observes how the model reacts, and fits a small linear model around it. {res.input_type === 'email' ? 'Weights are per word.' : 'Rules show the feature ranges that mattered.'}</p>
              <ExplainerPanel res={res.explanations.lime} kind="LIME" /></Collapsible>
          </div>
          <Card className="p-4 text-xs text-slate-400 space-y-1"><div className="label mb-1">Limitations</div>
            <p>• Explanations describe the <em>model</em>, not ground truth: a feature that “increases risk” is a statistical pattern learned from training data.</p>
            <p>• SHAP explains the model before probability calibration; LIME explains the calibrated probability and can vary slightly between runs.</p>
            <p>• Explanations depend on the training corpus; see the Model Performance page for dataset limitations.</p></Card>
        </div>
      )}
    </div>
  )
}
