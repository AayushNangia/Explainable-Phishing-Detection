import axios from 'axios'

const client = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:8000',
  timeout: 60000,
})

/** Turn any axios error into a short, human-readable message. */
export function errorMessage(err) {
  if (err.code === 'ECONNABORTED') return 'The request timed out. The analysis is taking too long — please try again.'
  if (!err.response) return 'Cannot reach the backend API. Make sure the FastAPI server is running (uvicorn main:app --reload) on port 8000.'
  const d = err.response.data?.detail
  if (typeof d === 'string') return d
  if (Array.isArray(d)) return d.map((x) => x.msg?.replace('Value error, ', '')).filter(Boolean).join('; ') || 'Invalid input.'
  return `Server error (${err.response.status}).`
}

export const api = {
  health: () => client.get('/api/health').then((r) => r.data),
  settings: () => client.get('/api/settings').then((r) => r.data),
  analyzeUrl: (url) => client.post('/api/analyze/url', { url }).then((r) => r.data),
  analyzeEmail: (payload) => client.post('/api/analyze/email', payload).then((r) => r.data),
  history: (params) => client.get('/api/history', { params }).then((r) => r.data),
  historyItem: (id) => client.get(`/api/history/${id}`).then((r) => r.data),
  deleteScan: (id) => client.delete(`/api/history/${id}`).then((r) => r.data),
  clearHistory: () => client.delete('/api/history').then((r) => r.data),
  stats: () => client.get('/api/dashboard/stats').then((r) => r.data),
  performance: () => client.get('/api/models/performance').then((r) => r.data),
}
