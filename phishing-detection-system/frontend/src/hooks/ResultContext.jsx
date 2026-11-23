import { createContext, useContext, useState } from 'react'

const Ctx = createContext(null)

/** Keeps the most recent real analysis result so the Explainability page can show it. */
export function ResultProvider({ children }) {
  const [latest, setLatest] = useState(null)
  return <Ctx.Provider value={{ latest, setLatest }}>{children}</Ctx.Provider>
}
export const useLatestResult = () => useContext(Ctx)
