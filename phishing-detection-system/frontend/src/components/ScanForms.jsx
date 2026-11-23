import { useState } from 'react'
import { Link2, Mail, Search } from 'lucide-react'
import { Alert } from './ui'
import { api, errorMessage } from '../services/api'
import { useLatestResult } from '../hooks/ResultContext'

const URL_EXAMPLES = [
  'https://www.wikipedia.org/wiki/Machine_learning',
  'http://192.168.4.23/secure/login.php?acct=verify',
  'http://paypal.com.secure-login.verify-account.example.top/webscr?cmd=_login',
  'http://a.b.c.d.login.update.example.com/account',
]
const EMAIL_EXAMPLES = [
  { label: 'OTP request', subject: 'Action required: verify your account', sender: 'PayPal Support <security@paypa1-help.top>', body: 'Dear customer,\n\nWe detected unusual activity. Your account will be suspended within 24 hours. Reply with your password and the OTP sent to your phone, or click here to verify: http://192.168.10.5/verify\n\nSecurity Team' },
  { label: 'Account suspension', subject: 'FINAL NOTICE: account locked', sender: 'support@gmail.com', body: 'Your bank account has been locked. Confirm your identity immediately by entering your credit card number and CVV at the link below or your account will be permanently closed.\nhttp://bit.ly/3abcXYZ' },
  { label: 'Normal email', subject: 'Sprint review notes', sender: 'priya@company.com', body: 'Hi team,\n\nThanks for joining the sprint review today. I have attached the notes. Please add any action items I missed before Thursday and we can discuss them in the next stand-up.\n\nBest,\nPriya' },
]

export function UrlScanForm({ onResult, compact = false }) {
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const { setLatest } = useLatestResult()
  const submit = async (e) => {
    e.preventDefault()
    if (!url.trim()) { setError('Please enter a URL to analyse.'); return }
    setLoading(true); setError(null)
    try { const r = await api.analyzeUrl(url.trim()); setLatest(r); onResult?.(r) } catch (err) { setError(errorMessage(err)) } finally { setLoading(false) }
  }
  return (
    <form onSubmit={submit} className="space-y-3">
      <div className="flex flex-col sm:flex-row gap-2">
        <div className="relative flex-1"><Link2 size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input aria-label="URL to analyse" className="!pl-9 font-mono" placeholder="https://example.com/login" value={url} onChange={(e) => setUrl(e.target.value)} disabled={loading} maxLength={2048} /></div>
        <button className="btn-primary" disabled={loading}><Search size={16} />{loading ? 'Analysing…' : 'Analyze'}</button>
      </div>
      {!compact && <div className="flex flex-wrap gap-2 items-center text-xs text-slate-500"><span>Try an input (the model and rules decide the result):</span>
        {URL_EXAMPLES.map((u) => <button type="button" key={u} className="btn-ghost !py-1 !px-2 !text-[11px] font-mono max-w-[260px] truncate" onClick={() => setUrl(u)} title={u}>{u.replace(/^https?:\/\//, '').slice(0, 34)}…</button>)}</div>}
      {loading && <Alert kind="info">Running static analysis, ML prediction, SHAP and LIME… the URL is never opened.</Alert>}
      {error && <Alert kind="error" title="Analysis failed">{error}</Alert>}
    </form>
  )
}

export function EmailScanForm({ onResult, compact = false }) {
  const [f, setF] = useState({ subject: '', sender: '', body: '' })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const { setLatest } = useLatestResult()
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value })
  const submit = async (e) => {
    e.preventDefault()
    if (!f.body.trim()) { setError('Please paste the email or message body.'); return }
    setLoading(true); setError(null)
    try { const r = await api.analyzeEmail({ subject: f.subject, body: f.body, sender: f.sender.trim() || null }); setLatest(r); onResult?.(r) } catch (err) { setError(errorMessage(err)) } finally { setLoading(false) }
  }
  return (
    <form onSubmit={submit} className="space-y-3">
      <div className="grid sm:grid-cols-2 gap-3">
        <div><label className="label">Subject</label><input value={f.subject} onChange={set('subject')} placeholder="Email subject" maxLength={500} disabled={loading} /></div>
        <div><label className="label">Sender (optional)</label><input value={f.sender} onChange={set('sender')} placeholder="Name <address@domain.com>" maxLength={320} disabled={loading} /></div>
      </div>
      <div><label className="label">Body</label><textarea rows={compact ? 4 : 9} value={f.body} onChange={set('body')} placeholder="Paste the e-mail or message text here…" maxLength={20000} disabled={loading} /></div>
      <div className="flex flex-wrap gap-2 items-center">
        <button className="btn-primary" disabled={loading}><Mail size={16} />{loading ? 'Analysing…' : 'Analyze'}</button>
        {!compact && <><span className="text-xs text-slate-500 ml-2">Fill with an example:</span>{EMAIL_EXAMPLES.map((x) => <button type="button" key={x.label} className="btn-ghost !py-1 !px-2 !text-xs" onClick={() => setF({ subject: x.subject, sender: x.sender, body: x.body })}>{x.label}</button>)}</>}
      </div>
      {loading && <Alert kind="info">Running NLP preprocessing, rules, ML prediction, SHAP and LIME…</Alert>}
      {error && <Alert kind="error" title="Analysis failed">{error}</Alert>}
    </form>
  )
}
