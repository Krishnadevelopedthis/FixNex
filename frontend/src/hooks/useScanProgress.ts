import * as React from "react"
import { useQueryClient } from "@tanstack/react-query"
import { apiWebSocketUrl, tokenStore } from "@/services/api"
import type { Scan } from "@/types"

/**
 * Live scan progress.
 *
 * Subscribes to the scan's WebSocket, and falls back to polling if the socket
 * cannot be established (for example behind a proxy that does not upgrade).
 */
export function useScanProgress(scanId: number | null, enabled: boolean) {
  const [live, setLive] = React.useState<Partial<Scan> | null>(null)
  const [connected, setConnected] = React.useState(false)
  const queryClient = useQueryClient()

  React.useEffect(() => {
    if (!scanId || !enabled) return
    const token = tokenStore.get()
    // Built from the configured API base, not window.location: in production
    // the API is on a different host from the app.
    const base = apiWebSocketUrl(`/scans/${scanId}/progress`)
    const url = token ? `${base}?token=${encodeURIComponent(token)}` : base

    let socket: WebSocket | null = null
    let closedByUs = false

    try {
      socket = new WebSocket(url)
    } catch {
      return
    }

    socket.onopen = () => setConnected(true)
    socket.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data)
        setLive(payload)
        if (["COMPLETED", "FAILED", "CANCELLED"].includes(payload.status)) {
          queryClient.invalidateQueries({ queryKey: ["scan", scanId] })
          queryClient.invalidateQueries({ queryKey: ["findings"] })
          queryClient.invalidateQueries({ queryKey: ["dashboard"] })
        }
      } catch {
        // Ignore malformed frames rather than tearing down the connection.
      }
    }
    socket.onclose = () => {
      setConnected(false)
      if (!closedByUs) queryClient.invalidateQueries({ queryKey: ["scan", scanId] })
    }
    socket.onerror = () => setConnected(false)

    return () => {
      closedByUs = true
      socket?.close()
    }
  }, [scanId, enabled, queryClient])

  return { live, connected }
}
