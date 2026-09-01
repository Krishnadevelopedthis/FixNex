import * as React from "react"

type Theme = "light" | "dark"
const STORAGE_KEY = "prcampus.theme"

const ThemeContext = React.createContext<{ theme: Theme; toggle: () => void }>({
  theme: "dark",
  toggle: () => {},
})

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [theme, setTheme] = React.useState<Theme>(() => {
    const stored = localStorage.getItem(STORAGE_KEY) as Theme | null
    if (stored === "light" || stored === "dark") return stored
    return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark"
  })

  React.useEffect(() => {
    document.documentElement.classList.toggle("dark", theme === "dark")
    localStorage.setItem(STORAGE_KEY, theme)
  }, [theme])

  const toggle = React.useCallback(() => setTheme((t) => (t === "dark" ? "light" : "dark")), [])
  const value = React.useMemo(() => ({ theme, toggle }), [theme, toggle])
  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
}

export function useTheme() {
  return React.useContext(ThemeContext)
}
