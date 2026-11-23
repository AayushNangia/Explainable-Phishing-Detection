import { useState } from 'react'
import { Card, PageHeader } from '../components/ui'
import { EmailScanForm, UrlScanForm } from '../components/ScanForms'
import ResultView from '../components/ResultView'
import { useLatestResult } from '../hooks/ResultContext'

export function UrlScanner() {
  const { latest } = useLatestResult()
  const [result, setResult] = useState(latest?.input_type === 'url' ? latest : null)
  return (
    <div>
      <PageHeader title="URL Scanner" subtitle="Static analysis of a URL with the trained model, security rules and explainable AI. The URL is treated as untrusted text and is never opened." />
      <Card className="p-5 mb-6"><UrlScanForm onResult={setResult} /></Card>
      {result && <ResultView result={result} />}
    </div>
  )
}

export function EmailScanner() {
  const { latest } = useLatestResult()
  const [result, setResult] = useState(latest?.input_type === 'email' ? latest : null)
  return (
    <div>
      <PageHeader title="Email / Message Scanner" subtitle="NLP preprocessing, TF-IDF classification, linguistic indicators and rules. Message text is analysed in memory and not stored unless enabled by the administrator." />
      <Card className="p-5 mb-6"><EmailScanForm onResult={setResult} /></Card>
      {result && <ResultView result={result} />}
    </div>
  )
}
