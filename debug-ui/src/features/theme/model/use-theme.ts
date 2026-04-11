import { useEffect, useMemo, useState } from 'react'
import type { ThemeMode } from '@/shared/types/debug'

export function useTheme() {
  const [theme, setTheme] = useState<ThemeMode>(() => {
    const stored = localStorage.getItem('debug-ui-theme')
    if (stored === 'dark' || stored === 'light' || stored === 'system') return stored
    return 'system'
  })

  const isDark = useMemo(() => {
    if (theme === 'dark') return true
    if (theme === 'light') return false
    return window.matchMedia('(prefers-color-scheme: dark)').matches
  }, [theme])

  useEffect(() => {
    localStorage.setItem('debug-ui-theme', theme)
    document.documentElement.classList.toggle('dark', isDark)
  }, [theme, isDark])

  const toggleTheme = () => {
    setTheme((t) => (t === 'dark' ? 'light' : t === 'light' ? 'system' : 'dark'))
  }

  return { theme, toggleTheme }
}
