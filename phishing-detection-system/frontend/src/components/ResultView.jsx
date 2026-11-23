import { AlertOctagon, BrainCircuit, Cpu, FileSearch, Lightbulb, ListChecks, Microscope, ScrollText, ShieldAlert, Sparkles } from 'lucide-react'
import { Alert, Card, ClassBadge, Collapsible, Empty } from './ui'
import { ContributionChart, RiskBar } from './charts'
import { CLASS_STYLES, SEVERITY_STYLES, pct } from '../lib'

const CAT_COLORS = { urgency: 'bg-amber-500/30', threat: 'bg-red-500/30', credential: 'bg-red-500/40', financial: 'bg-orange-500/30', reward: 'bg-fuchsia-500/30', generic_greeting: 'bg-sky-500/25', click_bait: 'bg-violet-500/30' }

export function HighlightedText({ text, spans }) {
  if (!text) return null
  const parts = []; let last = 0
  spans.forEach((s, i) => {
    parts.push(text.slice(last, s.start))
    parts.push(<mark key={i} title={s.category.replace('_', ' ')} className={`${CAT_COLORS[s.category] || 'bg-amber-500/30'} text-white rounded px-0.5`}>{text.slice(s.start, s.end)}</mark>)
    last = s.end
  })
  parts.push(text.slice(last))
  return <div className="whitespace-pre-wrap text-sm leading-relaxed bg-ink-950 rounded-lg p-3 max-h-64 overflow-auto border border-ink-600/60">{parts}</div>
}

export function ExplainerPanel({ res, kind }) {
  if (!res) return null
  if (!res.available) return <Alert kind="warning" title={`${kind} unavailable`}>{res.reason}</Alert>
  const isShap = kind === 'SHAP'
  return (
    <div>
      <ContributionChart items={res.features} valueKey={isShap ? 'shap_value' : 'weight'} unit={isShap ? `SHAP value (${res.unit})` : 'LIME weight'} />
      <div className="overflow-x-auto mt-3">
        <table className="w-full text-xs">
          <thead><tr className="text-left text-slate-500 border-b border-ink-600/60"><th className="py-1.5 pr-2">Feature</th>{isShap && <th className="pr-2">Value</th>}<th className="pr-2">{isShap ? 'SHAP' : 'Weight'}</th><th>Effect</th></tr></thead>
          <tbody>{res.features.map((f, i) => {
            const v = isShap ? f.shap_value : f.weight
            return (<tr key={i} className="border-b border-ink-700/60"><td className="py-1.5 pr-2 text-slate-200">{f.feature}{f.description && <div className="text-[10px] text-slate-500">{f.description}</div>}</td>
              {isShap && <td className="pr-2 font-mono">{Number.isInteger(f.value) ? f.value : f.value.toFixed(3)}</td>}
              <td className={`pr-2 font-mono ${v > 0 ? 'text-red-300' : 'text-emerald-300'}`}>{v > 0 ? '+' : ''}{v.toFixed(4)}</td><td className="text-slate-400">{f.direction}</td></tr>)
          })}</tbody>
        </table>
      </div>
      {isShap && <div className="text-[11px] text-slate-500 mt-2">Model: {res.model} · base value {res.base_value.toFixed(3)} ({res.unit})</div>}
      <p className="text-[11px] text-slate-500 mt-1">{res.note}</p>
    </div>
  )
}

export default function ResultView({ result: r }) {
  const s = CLASS_STYLES[r.classification]
  const isUrl = r.input_type === 'url'
  return (
    <div className="space-y-4">
      {r.mode && !r.mode.ml_available && <Alert kind="warning" title="DEMO MODE — MODEL NOT TRAINED">{r.mode.warning}</Alert>}
      {r.saved === false && <Alert kind="warning">This result could not be saved to history.</Alert>}
      <div className="grid xl:grid-cols-5 gap-4 items-start">
        {/* LEFT */}
        <div className="xl:col-span-2 space-y-4">
          <Card className={`p-5 border ${s.border}`}>
            <div className="flex items-center justify-between"><span className="label">Overall classification</span><ClassBadge value={r.classification} size="lg" /></div>
            <div className="mt-4 flex items-end gap-2"><span className={`text-5xl font-bold ${s.text}`}>{Math.round(r.risk_score)}</span><span className="text-slate-400 mb-1.5">/ 100 risk score</span></div>
            <div className="mt-4"><RiskBar score={r.risk_score} tSafe={r.hybrid.t_safe} tPhish={r.hybrid.t_phish} classification={r.classification} /></div>
            <div className="mt-4 text-xs text-slate-400 break-all"><span className="label block mb-0.5">{isUrl ? 'Analysed URL (never opened)' : 'Subject'}</span><span className="font-mono text-slate-300">{r.display_input || r.input_summary}</span></div>
          </Card>

          <Card className="p-5">
            <div className="label mb-3 flex items-center gap-1.5"><Cpu size={14} /> Hybrid score breakdown</div>
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div className="bg-ink-950 rounded-lg p-3"><div className="text-xs text-slate-400">ML probability</div><div className="text-xl font-semibold text-white">{r.ml.available ? pct(r.ml.probability) : 'N/A'}</div>
                <div className="text-[10px] text-slate-500">{r.ml.available ? `${r.ml.model_name} · calibrated` : 'model not trained'}</div></div>
              <div className="bg-ink-950 rounded-lg p-3"><div className="text-xs text-slate-400">Rule risk</div><div className="text-xl font-semibold text-white">{pct(r.rules.risk)}</div>
                <div className="text-[10px] text-slate-500">{r.rules.findings.length} rule(s) triggered</div></div>
            </div>
            <p className="text-xs text-slate-400 mt-3 font-mono">{r.hybrid.formula}</p>
            <p className="text-xs text-slate-500 mt-1">{r.ml.available ? <>α = {r.hybrid.alpha} (selected on validation data). ML part {(r.hybrid.ml_component * 100).toFixed(1)} + rule part {(r.hybrid.rule_component * 100).toFixed(1)} = {r.risk_score}.</> : 'Rules-only fallback with untuned default thresholds.'}</p>
            <p className="text-[11px] text-slate-500 mt-2">“ML probability” is a calibrated probability estimate (Platt scaling), not a guarantee. {r.ml.available && `Model: ${r.ml.model_name}.`}</p>
          </Card>

          <Card className="p-5">
            <div className="label mb-2 flex items-center gap-1.5"><Lightbulb size={14} /> Security advisory</div>
            <div className={`font-medium ${s.text} mb-3`}>{r.advisory.headline}</div>
            <ul className="space-y-2 text-sm">{[...r.advisory.actions, ...r.advisory.contextual].map((a, i) => <li key={i} className="flex gap-2"><ShieldAlert size={15} className={`${s.text} mt-0.5 shrink-0`} /><span>{a}</span></li>)}</ul>
            <p className="text-[11px] text-slate-500 mt-4 border-t border-ink-600/60 pt-3">{r.advisory.disclaimer}</p>
          </Card>
        </div>

        {/* RIGHT */}
        <div className="xl:col-span-3 space-y-4">
          <Collapsible title="Why was it classified this way?" icon={Sparkles}><p className="text-sm text-slate-300 leading-relaxed">{r.explanation_summary}</p></Collapsible>

          <Collapsible title={`Rule-based alerts (${r.rules.findings.length})`} icon={AlertOctagon} right={<span className="text-[10px] px-2 py-0.5 rounded bg-violet-500/15 text-violet-300 border border-violet-500/30">SOURCE: SECURITY RULES</span>}>
            {r.rules.findings.length === 0 ? <Empty>No security rules were triggered.</Empty> :
              <ul className="space-y-2">{r.rules.findings.map((f) => (
                <li key={f.rule_id} className="rounded-lg bg-ink-950 border border-ink-600/60 p-3">
                  <div className="flex items-center gap-2 flex-wrap"><span className={`text-[10px] uppercase px-1.5 py-0.5 rounded border ${SEVERITY_STYLES[f.severity]}`}>{f.severity}</span>
                    <span className="font-medium text-sm text-white">{f.title}</span><span className="ml-auto text-[10px] text-slate-500 font-mono">{f.rule_id} · w={f.weight}</span></div>
                  <p className="text-xs text-slate-400 mt-1">{f.description}</p>
                  {f.evidence?.length > 0 && <div className="flex flex-wrap gap-1.5 mt-2">{f.evidence.map((e, i) => <code key={i} className="text-[11px] bg-ink-700 rounded px-1.5 py-0.5 text-slate-300 break-all">{e}</code>)}</div>}
                </li>))}</ul>}
          </Collapsible>

          <Collapsible title="Top suspicious signals from the ML model" icon={Cpu} right={<span className="text-[10px] px-2 py-0.5 rounded bg-blue-500/15 text-blue-300 border border-blue-500/30">SOURCE: ML (SHAP)</span>}>
            {!r.ml.available ? <Empty>No trained model — no ML findings.</Empty> : r.ml.findings.length === 0 ? <Empty>No features pushed this input toward phishing.</Empty> :
              <ul className="space-y-1.5 text-sm">{r.ml.findings.map((f, i) => <li key={i} className="flex items-start gap-2"><span className="text-red-300 font-mono text-xs mt-0.5">+{f.contribution.toFixed(3)}</span><span><span className="text-white">{f.feature}</span>{f.description && <span className="text-slate-500"> — {f.description}</span>} <span className="text-slate-400 text-xs">(value {Number.isInteger(f.value) ? f.value : f.value.toFixed(2)})</span></span></li>)}</ul>}
          </Collapsible>

          <Collapsible title="SHAP — feature contributions" icon={BrainCircuit}><ExplainerPanel res={r.explanations.shap} kind="SHAP" /></Collapsible>
          <Collapsible title="LIME — local explanation" icon={Microscope}><ExplainerPanel res={r.explanations.lime} kind="LIME" /></Collapsible>

          {isUrl ? (
            <Collapsible title="Extracted URL features" icon={ListChecks} defaultOpen={false}>
              <div className="overflow-x-auto"><table className="w-full text-xs"><thead><tr className="text-left text-slate-500 border-b border-ink-600/60"><th className="py-1.5">Feature</th><th>Value</th><th>Meaning</th><th>ML input</th></tr></thead>
                <tbody>{Object.entries(r.features).map(([k, v]) => <tr key={k} className="border-b border-ink-700/60"><td className="py-1.5 font-mono text-slate-200">{k}</td><td className="font-mono">{v.value}</td><td className="text-slate-400">{v.description}</td><td>{v.used_by_ml ? '✓' : 'rules only'}</td></tr>)}</tbody></table></div>
            </Collapsible>
          ) : (
            <>
              <Collapsible title="Suspicious phrases (highlighted)" icon={FileSearch}>
                {r.highlight_text ? <HighlightedText text={r.highlight_text} spans={r.highlights} /> : <Empty>The message body is not stored in history.</Empty>}
                {r.highlights?.length > 0 && <div className="flex flex-wrap gap-2 mt-3 text-[11px]">{Object.keys(CAT_COLORS).filter((c) => r.highlights.some((h) => h.category === c)).map((c) => <span key={c} className={`${CAT_COLORS[c]} rounded px-2 py-0.5`}>{c.replace('_', ' ')}</span>)}</div>}
              </Collapsible>
              <Collapsible title="NLP findings & link analysis" icon={ScrollText} defaultOpen={false}>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-center mb-3">{Object.entries(r.nlp.indicator_counts).map(([k, v]) => <div key={k} className="bg-ink-950 rounded-lg p-2"><div className="text-lg text-white font-semibold">{v}</div><div className="text-[10px] text-slate-400">{k.replace('_', ' ')}</div></div>)}</div>
                <p className="text-xs text-slate-500 mb-3">{r.nlp.linguistic_note}</p>
                {r.links?.length ? <ul className="space-y-1.5 text-xs">{r.links.map((l, i) => <li key={i} className="bg-ink-950 rounded p-2"><code className="break-all text-slate-300">{l.url}</code><div className="text-slate-500">link rule risk {pct(l.rule_risk, 0)}{l.findings.length > 0 && ` — ${l.findings.join(', ')}`} (analysed statically, never opened)</div></li>)}</ul> : <Empty>No links found in the message.</Empty>}
              </Collapsible>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
