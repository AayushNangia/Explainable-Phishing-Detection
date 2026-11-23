import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  test: { environment: 'jsdom', environmentOptions: { jsdom: { url: 'http://localhost:5173' } }, testTimeout: 60000, globals: true, setupFiles: ['./src/tests/setup.js'] },
})
