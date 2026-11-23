// jsdom has no ResizeObserver (needed by Recharts' ResponsiveContainer)
globalThis.ResizeObserver = class { observe() {} unobserve() {} disconnect() {} }
