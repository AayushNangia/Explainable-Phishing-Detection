// Integration smoke tests: render the real pages against a RUNNING backend (http://localhost:8000).
// Start the API first:  uvicorn main:app --port 8000     then:  npm test
import { render, screen, waitFor, fireEvent, cleanup } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it } from 'vitest'
import App from '../App'
import { ResultProvider } from '../hooks/ResultContext'

const at = (path) => render(<MemoryRouter initialEntries={[path]}><ResultProvider><App /></ResultProvider></MemoryRouter>)
afterEach(cleanup)

describe('frontend ↔ backend', () => {
  it('landing page renders with Get Started', () => {
    at('/')
    expect(screen.getByText(/Get Started/i)).toBeTruthy()
    expect(screen.getAllByText('DETECT').length).toBeGreaterThan(0)
  })

  it('URL scanner: submits a URL and shows classification, SHAP and LIME', async () => {
    at('/app/url')
    fireEvent.change(screen.getByLabelText('URL to analyse'), { target: { value: 'http://192.168.4.23/secure/login.php?acct=verify' } })
    fireEvent.click(screen.getByRole('button', { name: /^Analyze$/i }))
    await waitFor(() => expect(screen.getByText('Overall classification')).toBeTruthy(), { timeout: 30000 })
    expect(screen.getAllByText('PHISHING').length).toBeGreaterThan(0)
    expect(screen.getAllByText(/IP address used instead of a domain name/).length).toBeGreaterThan(0)
    expect(screen.getByText(/SHAP — feature contributions/)).toBeTruthy()
    expect(screen.getByText(/LIME — local explanation/)).toBeTruthy()
  })

  it('URL scanner: shows a readable error for an unsupported scheme', async () => {
    at('/app/url')
    fireEvent.change(screen.getByLabelText('URL to analyse'), { target: { value: 'javascript:alert(1)' } })
    fireEvent.click(screen.getByRole('button', { name: /^Analyze$/i }))
    await waitFor(() => expect(screen.getByText(/not supported/i)).toBeTruthy(), { timeout: 15000 })
  })

  it('Email scanner: analyses a message and highlights phrases', async () => {
    at('/app/email')
    fireEvent.click(screen.getByRole('button', { name: 'OTP request' }))
    fireEvent.click(screen.getByRole('button', { name: /^Analyze$/i }))
    await waitFor(() => expect(screen.getByText('Overall classification')).toBeTruthy(), { timeout: 30000 })
    expect(document.querySelectorAll('mark').length).toBeGreaterThan(0)
  })

  it('Dashboard, Model Performance, History and Settings load real data', async () => {
    at('/app'); await waitFor(() => expect(screen.getByText('URLs analysed')).toBeTruthy(), { timeout: 15000 }); cleanup()
    at('/app/models'); await waitFor(() => expect(screen.getByText(/Model comparison/)).toBeTruthy(), { timeout: 15000 }); expect(screen.getAllByText(/Random Forest/).length).toBeGreaterThan(0); cleanup()
    at('/app/history'); await waitFor(() => expect(screen.getByText(/record\(s\)/)).toBeTruthy(), { timeout: 15000 }); cleanup()
    at('/app/settings'); await waitFor(() => expect(screen.getByText('Active backend')).toBeTruthy(), { timeout: 15000 })
  })
})
