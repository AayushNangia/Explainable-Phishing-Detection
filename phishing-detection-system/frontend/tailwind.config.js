/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        ink: { 950: '#070d1a', 900: '#0b1220', 800: '#111a2e', 700: '#18233d', 600: '#22304f', 500: '#2d3d62' },
        brand: { DEFAULT: '#3b82f6', purple: '#8b5cf6' },
        safe: '#10b981', warn: '#f59e0b', danger: '#ef4444',
      },
      fontFamily: { sans: ['Inter', 'system-ui', 'Segoe UI', 'sans-serif'], mono: ['JetBrains Mono', 'ui-monospace', 'Consolas', 'monospace'] },
    },
  },
  plugins: [],
}
