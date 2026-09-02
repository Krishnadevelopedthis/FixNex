import * as React from "react"
import { AnimatePresence, motion } from "motion/react"
import { CheckCircle2, Info, X, XCircle } from "lucide-react"
import { cn } from "@/lib/utils"
import { TRANSITION, toastVariants, useMotionPrefs } from "@/lib/motion"

type ToastKind = "success" | "error" | "info"
type Toast = { id: number; kind: ToastKind; title: string; description?: string }

const ToastContext = React.createContext<{
  toast: (kind: ToastKind, title: string, description?: string) => void
}>({ toast: () => {} })

export function useToast() {
  return React.useContext(ToastContext)
}

/** Extracts the API's structured error message for display. */
export function errorMessage(error: unknown, fallback = "Something went wrong."): string {
  const data = (error as any)?.response?.data
  return data?.error?.message ?? (error as any)?.message ?? fallback
}

const ICONS = { success: CheckCircle2, error: XCircle, info: Info }
const STYLES = {
  success: "border-success/30 bg-card text-foreground [&_svg]:text-success",
  error: "border-destructive/30 bg-card text-foreground [&_svg]:text-destructive",
  info: "border-border bg-card text-foreground [&_svg]:text-primary",
}

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = React.useState<Toast[]>([])
  const { transition, variants } = useMotionPrefs()

  const toast = React.useCallback((kind: ToastKind, title: string, description?: string) => {
    const id = Date.now() + Math.random()
    setToasts((prev) => [...prev, { id, kind, title, description }])
    setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), 5200)
  }, [])

  const dismiss = (id: number) => setToasts((prev) => prev.filter((t) => t.id !== id))

  return (
    <ToastContext.Provider value={{ toast }}>
      {children}
      <div className="pointer-events-none fixed bottom-4 right-4 z-[100] flex w-full max-w-sm flex-col gap-2">
        <AnimatePresence initial={false}>
        {toasts.map((t) => {
          const Icon = ICONS[t.kind]
          return (
            <motion.div
              key={t.id}
              role="status"
              layout
              variants={variants(toastVariants)}
              initial="hidden" animate="visible" exit="hidden"
              transition={transition(TRANSITION.base)}
              className={cn(
                "pointer-events-auto flex items-start gap-3 rounded-lg border p-3.5 shadow-lg",
                STYLES[t.kind]
              )}
            >
              <Icon className="mt-0.5 h-4 w-4 shrink-0" />
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium">{t.title}</p>
                {t.description && (
                  <p className="mt-0.5 break-words text-xs text-muted-foreground">{t.description}</p>
                )}
              </div>
              <button onClick={() => dismiss(t.id)} className="shrink-0 opacity-50 hover:opacity-100">
                <X className="h-3.5 w-3.5" />
              </button>
            </motion.div>
          )
        })}
        </AnimatePresence>
      </div>
    </ToastContext.Provider>
  )
}
