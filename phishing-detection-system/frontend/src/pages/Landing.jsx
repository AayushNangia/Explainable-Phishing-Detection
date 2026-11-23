import { Link } from 'react-router-dom'
import { ArrowRight, BrainCircuit, Cpu, Eye, FileSearch, Lightbulb, Lock, Scale, ScanSearch, ShieldCheck, Database } from 'lucide-react'
import { Logo } from '../components/Layout'

const STEPS = [
  { icon: ScanSearch, t: 'DETECT', d: 'A trained classifier and security rules classify a URL or message as SAFE, SUSPICIOUS or PHISHING with a 0–100 risk score.' },
  { icon: BrainCircuit, t: 'EXPLAIN', d: 'SHAP and LIME show which features pushed the decision, alongside the explicit rules that fired.' },
  { icon: Lightbulb, t: 'ADVISE', d: 'Actionable, finding-specific recommendations tell you what to do next — and what never to do.' },
]
const FEATURES = [
  [Scale, 'Hybrid engine', 'Final risk = α·ML + (1−α)·Rules, with α and thresholds tuned on validation data.'],
  [Cpu, 'Three models compared', 'Logistic Regression, Decision Tree and Random Forest evaluated on a held-out test set.'],
  [FileSearch, 'NLP analysis', 'Text cleaning, TF-IDF, urgency / credential / threat lexicons and phrase highlighting.'],
  [Eye, 'Genuine explainability', 'SHAP and LIME computed from the real model and input — never fabricated.'],
  [Lock, 'Safe by design', 'Static analysis only. URLs are never opened, fetched or executed.'],
  [Database, 'Scan history', 'MongoDB-backed history with filters, details and deletion; privacy-first storage.'],
]
const TIPS = [
  'Legitimate organisations never ask for your password or OTP by e-mail, SMS or phone.',
  'Check the real domain, not the display name. Look-alike domains (paypa1.com) are common.',
  'Urgency and threats (“account suspended in 24 hours”) are pressure tactics.',
  'HTTPS only means the connection is encrypted — phishing sites use it too.',
  'When in doubt, type the official address yourself or call a number from the official website.',
  'Report phishing: in India, cybercrime.gov.in or helpline 1930.',
]

export default function Landing() {
  return (
    <div className="min-h-screen bg-ink-900">
      <header className="max-w-6xl mx-auto px-5 h-16 flex items-center justify-between"><Logo />
        <Link to="/app" className="btn-primary">Open dashboard <ArrowRight size={16} /></Link></header>

      <section className="max-w-6xl mx-auto px-5 pt-16 pb-20 text-center">
        <div className="inline-flex items-center gap-2 text-xs px-3 py-1 rounded-full border border-brand/30 bg-brand/10 text-blue-300 mb-6"><ShieldCheck size={14} /> Final-year B.Tech project · Explainable AI</div>
        <h1 className="text-4xl md:text-6xl font-bold text-white tracking-tight">Explainable Phishing Detection <br className="hidden md:block" />and <span className="bg-gradient-to-r from-brand to-brand-purple bg-clip-text text-transparent">Advisory System</span></h1>
        <p className="mt-6 text-slate-400 max-w-2xl mx-auto text-lg">Combines machine learning, NLP and explicit security rules to detect phishing URLs and messages — and explains <em>why</em> in plain language.</p>
        <Link to="/app" className="btn-primary mt-8 !px-6 !py-3 text-base">Get Started <ArrowRight size={18} /></Link>
      </section>

      <section className="max-w-6xl mx-auto px-5 pb-20 grid md:grid-cols-3 gap-4">
        {STEPS.map(({ icon: I, t, d }, i) => (
          <div key={t} className="card p-6 relative"><div className="h-11 w-11 rounded-lg bg-gradient-to-br from-brand/30 to-brand-purple/30 grid place-items-center mb-4"><I className="text-blue-300" size={22} /></div>
            <div className="text-xs text-slate-500 mb-1">STEP {i + 1}</div><h3 className="text-xl font-semibold text-white">{t}</h3><p className="text-sm text-slate-400 mt-2">{d}</p></div>))}
      </section>

      <section className="bg-ink-950/60 border-y border-ink-600/50 py-16"><div className="max-w-6xl mx-auto px-5">
        <h2 className="text-2xl font-semibold text-white text-center mb-10">Features</h2>
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">{FEATURES.map(([I, t, d]) => <div key={t} className="card p-5"><I size={20} className="text-brand-purple mb-3" /><h3 className="font-medium text-white">{t}</h3><p className="text-sm text-slate-400 mt-1">{d}</p></div>)}</div></div></section>

      <section className="max-w-6xl mx-auto px-5 py-16">
        <h2 className="text-2xl font-semibold text-white text-center mb-10">How it works</h2>
        <ol className="grid md:grid-cols-5 gap-3 text-sm">{['Input is validated and normalised (never fetched)', 'Features / TF-IDF are extracted', 'Security rules and the ML model each score the input', 'The hybrid engine combines both and applies tuned thresholds', 'SHAP, LIME and an advisory explain the result'].map((s, i) =>
          <li key={i} className="card p-4"><div className="h-7 w-7 rounded-full bg-brand/20 text-blue-300 grid place-items-center text-xs font-semibold mb-2">{i + 1}</div><span className="text-slate-300">{s}</span></li>)}</ol>
      </section>

      <section className="max-w-6xl mx-auto px-5 pb-20"><div className="card p-8">
        <h2 className="text-xl font-semibold text-white mb-4">Security awareness</h2>
        <ul className="grid md:grid-cols-2 gap-x-8 gap-y-3 text-sm text-slate-300">{TIPS.map((t) => <li key={t} className="flex gap-2"><ShieldCheck size={16} className="text-emerald-400 shrink-0 mt-0.5" />{t}</li>)}</ul>
        <p className="text-xs text-slate-500 mt-6">Automated classification is not a guarantee of safety. Always verify through an official channel.</p></div></section>
      <footer className="text-center text-xs text-slate-500 pb-8">PhishGuard XAI · Academic project · Detect · Explain · Advise</footer>
    </div>
  )
}
