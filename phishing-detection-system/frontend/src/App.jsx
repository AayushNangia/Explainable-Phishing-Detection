import { Navigate, Route, Routes } from 'react-router-dom'
import Layout from './components/Layout'
import Landing from './pages/Landing'
import Dashboard from './pages/Dashboard'
import { UrlScanner, EmailScanner } from './pages/Scanners'
import Explainability from './pages/Explainability'
import ModelPerformance from './pages/ModelPerformance'
import { HistoryPage, HistoryDetail } from './pages/History'
import Settings from './pages/Settings'

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route path="/app" element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="url" element={<UrlScanner />} />
        <Route path="email" element={<EmailScanner />} />
        <Route path="explainability" element={<Explainability />} />
        <Route path="models" element={<ModelPerformance />} />
        <Route path="history" element={<HistoryPage />} />
        <Route path="history/:id" element={<HistoryDetail />} />
        <Route path="settings" element={<Settings />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
