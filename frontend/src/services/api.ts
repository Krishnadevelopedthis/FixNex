import axios, { AxiosError } from "axios"

const TOKEN_KEY = "prcampus.access_token"
const REFRESH_KEY = "prcampus.refresh_token"

/**
 * Resolve the API base URL.
 *
 * In development this is a relative path Vite proxies. In production the API
 * lives on another host (Render) while the app is served from Vercel, so
 * VITE_API_URL supplies its origin.
 *
 * The `/api` suffix is appended when missing: every route in this client is
 * written relative to that prefix, and pointing the variable at a bare origin
 * is the natural mistake. Both `https://api.example.com` and
 * `https://api.example.com/api` therefore work.
 */
const getApiBaseUrl = (): string => {
  const configured = import.meta.env.VITE_API_URL
  if (!configured) return "/api"
  const trimmed = String(configured).replace(/\/+$/, "")
  return /\/api$/.test(trimmed) ? trimmed : `${trimmed}/api`
}

export const tokenStore = {
  get: () => localStorage.getItem(TOKEN_KEY),
  getRefresh: () => localStorage.getItem(REFRESH_KEY),
  set: (access: string, refresh: string) => {
    localStorage.setItem(TOKEN_KEY, access)
    localStorage.setItem(REFRESH_KEY, refresh)
  },
  clear: () => {
    localStorage.removeItem(TOKEN_KEY)
    localStorage.removeItem(REFRESH_KEY)
  },
}

const apiBaseUrl = getApiBaseUrl()

/**
 * Absolute ws:// or wss:// URL for a path under the API prefix.
 *
 * Deriving this from window.location would point the socket at the frontend
 * host, where nothing is listening once the API is deployed separately.
 */
export function apiWebSocketUrl(path: string): string {
  const absolute = /^https?:\/\//.test(apiBaseUrl)
  const url = new URL(
    absolute ? `${apiBaseUrl}${path}` : `${apiBaseUrl}${path}`,
    window.location.origin
  )
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:"
  return url.toString()
}
export const api = axios.create({
  baseURL: apiBaseUrl,
  headers: { "Content-Type": "application/json" },
  withCredentials: true,
})

// Log API base URL in development
if (import.meta.env.DEV) {
  console.log(`[API] Base URL: ${apiBaseUrl}`)
}

api.interceptors.request.use((config) => {
  const token = tokenStore.get()
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

// A single in-flight refresh shared by every queued request.
let refreshing: Promise<string | null> | null = null

async function refreshAccessToken(): Promise<string | null> {
  const refresh = tokenStore.getRefresh()
  if (!refresh) return null
  try {
    const { data } = await axios.post("/api/auth/refresh", { refresh_token: refresh })
    tokenStore.set(data.access_token, data.refresh_token)
    return data.access_token as string
  } catch {
    tokenStore.clear()
    return null
  }
}

api.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const original = error.config as any
    const isAuthCall = original?.url?.includes("/auth/login") || original?.url?.includes("/auth/refresh")

    if (error.response?.status === 401 && !original?._retried && !isAuthCall) {
      original._retried = true
      refreshing = refreshing ?? refreshAccessToken().finally(() => { refreshing = null })
      const token = await refreshing
      if (token) {
        original.headers.Authorization = `Bearer ${token}`
        return api(original)
      }
      tokenStore.clear()
      if (!window.location.pathname.startsWith("/login")) {
        window.location.href = "/login"
      }
    }
    return Promise.reject(error)
  }
)

/** Downloads a binary response and triggers a browser save. */
export async function downloadFile(url: string, fallbackName: string) {
  const response = await api.get(url, { responseType: "blob" })
  const disposition = response.headers["content-disposition"] as string | undefined
  const match = disposition?.match(/filename\*?=(?:UTF-8'')?"?([^";]+)"?/i)
  const filename = match ? decodeURIComponent(match[1]) : fallbackName

  const href = URL.createObjectURL(response.data)
  const anchor = document.createElement("a")
  anchor.href = href
  anchor.download = filename
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  URL.revokeObjectURL(href)
}
