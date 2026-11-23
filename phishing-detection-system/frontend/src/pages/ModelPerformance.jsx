import { useState } from 'react'
import { Bar, BarChart, CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { Alert, Card, Empty, PageHeader, Spinner } from '../components/ui'
import { ContributionChart, tipStyle } from '../components/charts'
import { useAsync } from '../hooks/useAsync'
import { api } from '../services/api'
import { fmtDate } from '../lib'

const COLORS = ['#3b82f6', '#f59e0b', '#8b5cf6']
const f4 = (v) => (v == null ? '—' : v.toFixed(4))

function ConfusionMatrix({ cm }) {
  const [[tn, fp], [fn, tp]] = cm
  const cell = (v, good, label) => <div className={`rounded-lg p-4 text-center border ${good ? 'bg-emerald-500/10 border-emerald-500/30' : 'bg-red-500/10 border-red-500/30'}`}><div className="text-2xl font-semibold text-white">{v.toLocaleString()}</div><div className="text-[11px] text-slate-400">{label}</div></div>
  return (
    <div className="grid grid-cols-[auto_1fr_1fr] gap-2 items-center text-xs text-slate-400 max-w-md">
      <div /><div className="text-center">Predicted legitimate</div><div className="text-center">Predicted phishing</div>
      <div className="[writing-mode:vertical-rl] rotate-180 text-center">Actual legit.</div>{cell(tn, true, 'True negative')}{cell(fp, false, 'False positive')}
      <div className="[writing-mode:vertical-rl] rotate-180 text-center">Actual phish.</div>{cell(fn, false, 'False negative')}{cell(tp, true, 'True positive')}
    </div>
  )
}

function TaskView({ m }) {
  const [sel, setSel] = useState(m.selected_model)
  const model = m.models.find((x) => x.name === sel)
  const cmp = m.models.map((x) => ({ name: x.name, Accuracy: x.test.accuracy, Precision: x.test.precision, Recall: x.test.recall, 'F1-score': x.test.f1, 'ROC-AUC': x.test.roc_auc }))
  const h = m.hybrid
  return (
    <div className="space-y-4">
      <Card className="p-5 grid md:grid-cols-4 gap-4 text-sm">
        <div><div className="label">Dataset</div><div className="text-white mt-1">{m.dataset_name}</div></div>
        <div><div className="label">Samples</div><div className="text-white mt-1">{m.dataset.usable_rows?.toLocaleString()} (train {m.dataset.n_train?.toLocaleString()} / val {m.dataset.n_val?.toLocaleString()} / test {m.dataset.n_test?.toLocaleString()})</div></div>
        <div><div className="label">Selected model</div><div className="text-white mt-1">{m.selected_model}</div><div className="text-[11px] text-slate-500">{m.selection_criterion}</div></div>
        <div><div className="label">Evaluated</div><div className="text-white mt-1">{fmtDate(m.evaluation_date)}</div></div>
        <div className="md:col-span-4 text-xs text-slate-400">{m.split}. Calibration: {m.calibration}.</div>
      </Card>
      {m.notes?.map((n, i) => <Alert key={i} kind="warning">{n}</Alert>)}

      <Card className="p-5"><div className="label mb-3">Model comparison — TEST set (held-out, used once)</div>
        <div style={{ height: 280 }}><ResponsiveContainer><BarChart data={cmp}><CartesianGrid stroke="#22304f" vertical={false} /><XAxis dataKey="name" stroke="#94a3b8" tick={{ fontSize: 12 }} />
          <YAxis domain={[Math.max(0, Math.floor(Math.min(...cmp.flatMap((c) => [c.Accuracy, c.Precision, c.Recall, c['F1-score']])) * 10) / 10 - 0.1), 1]} stroke="#64748b" tick={{ fontSize: 11 }} /><Tooltip contentStyle={tipStyle} formatter={(v) => v.toFixed(4)} cursor={{ fill: '#ffffff08' }} /><Legend />
          {['Accuracy', 'Precision', 'Recall', 'F1-score', 'ROC-AUC'].map((k, i) => <Bar key={k} dataKey={k} fill={['#3b82f6', '#06b6d4', '#10b981', '#8b5cf6', '#f59e0b'][i]} radius={[3, 3, 0, 0]} />)}</BarChart></ResponsiveContainer></div></Card>

      <Card className="p-5 overflow-x-auto"><div className="label mb-3">Detailed metrics (training metrics are for over-fitting diagnosis only)</div>
        <table className="w-full text-xs"><thead><tr className="text-left text-slate-500 border-b border-ink-600/60"><th className="py-2">Model</th><th>Split</th><th>Accuracy</th><th>Precision</th><th>Recall</th><th>F1</th><th>ROC-AUC</th></tr></thead>
          <tbody>{m.models.flatMap((x) => ['train', 'validation', 'test'].map((sp) => <tr key={x.name + sp} className={`border-b border-ink-700/60 ${sp === 'test' ? 'bg-brand/5' : ''}`}><td className="py-1.5 text-white">{sp === 'train' ? <>{x.name}{x.name === m.selected_model && <span className="ml-2 text-[10px] text-emerald-300">selected</span>}</> : ''}</td>
            <td className={sp === 'test' ? 'text-blue-300 font-medium' : sp === 'train' ? 'text-slate-500' : 'text-slate-300'}>{sp}</td><td>{f4(x[sp].accuracy)}</td><td>{f4(x[sp].precision)}</td><td>{f4(x[sp].recall)}</td><td>{f4(x[sp].f1)}</td><td>{f4(x[sp].roc_auc)}</td></tr>))}</tbody></table></Card>

      <div className="grid lg:grid-cols-2 gap-4">
        <Card className="p-5"><div className="flex items-center gap-2 mb-3"><div className="label">Confusion matrix (test)</div>
          <select className="!w-auto !py-1 ml-auto" value={sel} onChange={(e) => setSel(e.target.value)}>{m.models.map((x) => <option key={x.name}>{x.name}</option>)}</select></div>
          <ConfusionMatrix cm={model.test.confusion_matrix} /><div className="text-[11px] text-slate-500 mt-3">Threshold 0.5 on uncalibrated model probability · n = {model.test.n.toLocaleString()}</div></Card>
        <Card className="p-5"><div className="label mb-3">ROC curves (test)</div>
          <div style={{ height: 280 }}><ResponsiveContainer><LineChart margin={{ left: 0, right: 10 }}><CartesianGrid stroke="#22304f" /><XAxis type="number" dataKey="fpr" domain={[0, 1]} stroke="#64748b" tick={{ fontSize: 11 }} label={{ value: 'False positive rate', position: 'insideBottom', offset: -2, fill: '#64748b', fontSize: 11 }} />
            <YAxis type="number" dataKey="tpr" domain={[0, 1]} stroke="#64748b" tick={{ fontSize: 11 }} /><Tooltip contentStyle={tipStyle} formatter={(v) => v.toFixed(3)} /><Legend />
            {m.models.map((x, i) => <Line key={x.name} data={x.roc_test} dataKey="tpr" name={`${x.name} (AUC ${x.test.roc_auc.toFixed(3)})`} stroke={COLORS[i]} dot={false} strokeWidth={2} />)}</LineChart></ResponsiveContainer></div></Card>
      </div>

      <Card className="p-5"><div className="label mb-1">Hybrid engine — parameters tuned on the validation set</div>
        <p className="text-xs text-slate-400 mb-3">α = {h.alpha} (constrained ≤ {h.alpha_max}; unconstrained validation optimum α = {h.unconstrained_best_alpha}) · SAFE &lt; {h.t_safe} ≤ SUSPICIOUS &lt; {h.t_phish} ≤ PHISHING. These are validation-optimal under the stated criteria, not claims of global optimality.</p>
        <ul className="text-xs text-slate-500 mb-4 list-disc pl-5">{Object.values(h.criteria).map((c, i) => <li key={i}>{c}</li>)}</ul>
        <div className="overflow-x-auto"><table className="w-full text-xs"><thead><tr className="text-left text-slate-500 border-b border-ink-600/60"><th className="py-2">System (TEST set)</th><th>Precision</th><th>Recall</th><th>F1</th><th>Accuracy</th></tr></thead>
          <tbody>{[['ML only (calibrated, ≥0.5)', h.test['ml_only@0.5']], ['Rules only (≥ phishing threshold)', h.test['rules_only@t_phish']], ['Hybrid — PHISHING decision', h.test['hybrid_phishing@t_phish']], ['Hybrid — flagged (SUSPICIOUS or PHISHING)', h.test['hybrid_flagged@t_safe']]].map(([n, v]) => <tr key={n} className="border-b border-ink-700/60"><td className="py-1.5 text-white">{n}</td><td>{f4(v.precision)}</td><td>{f4(v.recall)}</td><td>{f4(v.f1)}</td><td>{f4(v.accuracy)}</td></tr>)}</tbody></table></div>
        <div className="grid sm:grid-cols-3 gap-2 mt-4 text-center">{Object.entries(h.test.three_class_breakdown).map(([k, v]) => <div key={k} className="bg-ink-950 rounded-lg p-3 text-xs"><div className="font-semibold text-white">{k}</div><div className="text-slate-400">{v.true_phishing.toLocaleString()} actual phishing · {v.true_legitimate.toLocaleString()} actual legitimate</div></div>)}</div>
        <p className="text-[11px] text-slate-500 mt-2">Rules-only ROC-AUC {f4(h.test.rules_only_roc_auc)} · ML-only ROC-AUC {f4(h.test.ml_only_roc_auc)}. Rules are hand-written expert heuristics; they are not trained on this data.</p>
        <div style={{ height: 200 }} className="mt-4"><ResponsiveContainer><LineChart data={h.alpha_grid}><CartesianGrid stroke="#22304f" /><XAxis dataKey="alpha" stroke="#64748b" tick={{ fontSize: 11 }} label={{ value: 'α (validation)', position: 'insideBottom', offset: -2, fill: '#64748b', fontSize: 11 }} /><YAxis domain={['auto', 'auto']} stroke="#64748b" tick={{ fontSize: 11 }} /><Tooltip contentStyle={tipStyle} formatter={(v) => v.toFixed(4)} /><Line dataKey="pr_auc" name="PR-AUC" stroke="#8b5cf6" dot={false} strokeWidth={2} /></LineChart></ResponsiveContainer></div></Card>

      {m.feature_importance?.length > 0 && <Card className="p-5"><div className="label mb-3">Global feature importance — {m.selected_model}</div>
        <ContributionChart items={m.feature_importance.slice(0, 12).map((f) => ({ ...f, direction: 'importance' }))} valueKey="importance" /></Card>}
    </div>
  )
}

export default function ModelPerformance() {
  const { data, loading, error } = useAsync(api.performance)
  const [tab, setTab] = useState('url')
  return (
    <div>
      <PageHeader title="Model Performance" subtitle="Genuine evaluation results produced by the training scripts. Nothing here is hard-coded." />
      <div className="flex gap-2 mb-4">{[['url', 'URL model'], ['email', 'Email model']].map(([k, l]) => <button key={k} onClick={() => setTab(k)} className={`btn border ${tab === k ? 'bg-brand/20 border-brand/50 text-white' : 'bg-ink-800 border-ink-600 text-slate-400'}`}>{l}</button>)}</div>
      {loading && <Spinner />}{error && <Alert kind="error">{error}</Alert>}
      {data && (data[tab].trained === false ? <Alert kind="warning" title="MODEL NOT TRAINED">{data[tab].message}</Alert> : <TaskView key={tab} m={data[tab]} />)}
      {data && !data[tab] && <Empty>No data.</Empty>}
    </div>
  )
}
