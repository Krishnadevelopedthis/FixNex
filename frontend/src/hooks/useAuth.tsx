import * as React from "react"
import { useQueryClient } from "@tanstack/react-query"
import { authApi } from "@/services/endpoints"
import { tokenStore } from "@/services/api"
import type { CurrentUser } from "@/types"

interface AuthContextValue {
  user: CurrentUser | null
  loading: boolean
  login: (email: string, password: string) => Promise<void>
  logout: () => Promise<void>
  /** Permission check backed by the server's permission matrix. */
  can: (...permissions: string[]) => boolean
  canAny: (...permissions: string[]) => boolean
}

const AuthContext = React.createContext<AuthContextValue>({} as AuthContextValue)

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = React.useState<CurrentUser | null>(null)
  const [loading, setLoading] = React.useState(true)
  const queryClient = useQueryClient()

  React.useEffect(() => {
    let cancelled = false
    async function restore() {
      if (!tokenStore.get()) {
        setLoading(false)
        return
      }
      try {
        const me = await authApi.me()
        if (!cancelled) setUser(me)
      } catch {
        tokenStore.clear()
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    restore()
    return () => { cancelled = true }
  }, [])

  const login = React.useCallback(async (email: string, password: string) => {
    const data = await authApi.login(email, password)
    tokenStore.set(data.access_token, data.refresh_token)
    setUser(data.user)
    queryClient.clear()
  }, [queryClient])

  const logout = React.useCallback(async () => {
    try {
      await authApi.logout()
    } catch {
      // Signing out locally must succeed even if the request fails.
    }
    tokenStore.clear()
    setUser(null)
    queryClient.clear()
  }, [queryClient])

  const permissions = React.useMemo(() => new Set(user?.permissions ?? []), [user])
  const can = React.useCallback((...required: string[]) =>
    required.every((p) => permissions.has(p)), [permissions])
  const canAny = React.useCallback((...options: string[]) =>
    options.some((p) => permissions.has(p)), [permissions])

  const value = React.useMemo(
    () => ({ user, loading, login, logout, can, canAny }),
    [user, loading, login, logout, can, canAny]
  )
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  return React.useContext(AuthContext)
}
