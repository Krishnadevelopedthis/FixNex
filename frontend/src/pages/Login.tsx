import * as React from "react"
import { Navigate, useNavigate } from "react-router-dom"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { AlertCircle, Lock, Mail, ShieldCheck } from "lucide-react"
import { useAuth } from "@/hooks/useAuth"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { errorMessage } from "@/components/ui/toast"

const schema = z.object({
  email: z.string().min(1, "Email is required").email("Enter a valid email address"),
  password: z.string().min(1, "Password is required"),
})
type FormValues = z.infer<typeof schema>

const DEMO_ACCOUNTS = [
  { role: "Security Lead", email: "lead@fixnex.io", note: "Creates assessments, scope, assigns work" },
  { role: "Security Engineer", email: "engineer@fixnex.io", note: "Runs scans, verifies, retests" },
  { role: "Developer", email: "developer@fixnex.io", note: "Works assigned remediation only" },
  { role: "Administrator", email: "admin@fixnex.io", note: "Full access incl. users and settings" },
  { role: "Analyst", email: "analyst@fixnex.io", note: "Manual testing and evidence" },
  { role: "Auditor", email: "auditor@fixnex.io", note: "Read-only across the platform" },
]
const DEMO_PASSWORD = "DemoPass123!"

export default function LoginPage() {
  const { user, login, loading } = useAuth()
  const navigate = useNavigate()
  const [serverError, setServerError] = React.useState<string | null>(null)

  const form = useForm<FormValues>({
    resolver: zodResolver(schema),
    defaultValues: { email: "", password: "" },
  })

  if (!loading && user) return <Navigate to="/" replace />

  async function onSubmit(values: FormValues) {
    setServerError(null)
    try {
      await login(values.email, values.password)
      navigate("/", { replace: true })
    } catch (error) {
      setServerError(errorMessage(error, "Sign-in failed."))
    }
  }

  function fillDemo(email: string) {
    form.setValue("email", email)
    form.setValue("password", DEMO_PASSWORD)
    setServerError(null)
  }

  return (
    <div className="grid min-h-screen lg:grid-cols-2">
      {/* Brand panel */}
      <div className="relative hidden flex-col justify-between overflow-hidden bg-gradient-to-br from-primary/95 via-primary to-primary/70 p-10 text-primary-foreground lg:flex">
        <div
          className="pointer-events-none absolute inset-0 opacity-[0.07]"
          style={{
            backgroundImage:
              "radial-gradient(circle at 1px 1px, currentColor 1px, transparent 0)",
            backgroundSize: "28px 28px",
          }}
        />
        <div className="reveal relative flex items-center gap-2.5" style={{ animationDelay: "0ms" }}>
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-white/15">
            <ShieldCheck className="h-5 w-5" />
          </div>
          <span className="font-display text-xl font-bold tracking-[-0.02em]">FixNex</span>
        </div>

        <div className="relative max-w-md space-y-5">
          {/* Each line settles in turn, so the panel reads top to bottom rather
              than arriving as one block. Delays are staggered per element. */}
          <h1
            className="reveal text-balance font-display text-[2.5rem] font-bold leading-[1.08] tracking-[-0.03em]"
            style={{ animationDelay: "80ms" }}
          >
            One platform for the whole security assessment lifecycle.
          </h1>
          <p
            className="reveal max-w-[38ch] text-pretty text-[0.95rem] leading-[1.7] text-primary-foreground/80"
            style={{ animationDelay: "260ms" }}
          >
            Reconnaissance, scanning, manual verification, evidence, CVSS and contextual
            risk, remediation, retesting, audit and reporting — centralized instead of
            scattered across disconnected tools.
          </p>
          <div className="space-y-3 pt-3 text-[0.9rem]">
            {[
              "Scanner adapters normalize every tool into one finding format",
              "Correlation merges duplicate findings across scanners",
              "Scans are restricted to explicitly authorized scope",
              "Every action is written to an append-only audit trail",
            ].map((line, index) => (
              <div
                key={line}
                className="reveal flex items-start gap-2.5"
                style={{ animationDelay: `${440 + index * 140}ms` }}
              >
                <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-primary-foreground/70" />
                <span className="leading-relaxed text-primary-foreground/80">{line}</span>
              </div>
            ))}
          </div>
        </div>

        <p
          className="reveal relative text-[11px] font-medium uppercase tracking-[0.16em] text-primary-foreground/55"
          style={{ animationDelay: "1000ms" }}
        >
          For authorized security testing only
        </p>
      </div>

      {/* Form panel */}
      <div className="flex items-center justify-center px-5 py-10">
        <div className="w-full max-w-md space-y-7">
          <div className="space-y-2 lg:hidden">
            <div className="flex items-center gap-2.5">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary text-primary-foreground">
                <ShieldCheck className="h-5 w-5" />
              </div>
              <span className="font-display text-xl font-bold tracking-[-0.02em]">FixNex</span>
            </div>
          </div>

          <div className="space-y-1.5">
            <h2 className="font-display text-[1.75rem] font-bold tracking-[-0.02em]">Sign in</h2>
            <p className="text-[0.9rem] leading-relaxed text-muted-foreground">
              Use your FixNex account to continue.
            </p>
          </div>

          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4" noValidate>
            {serverError && (
              <div
                role="alert"
                className="flex items-start gap-2.5 rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive"
              >
                <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
                <span>{serverError}</span>
              </div>
            )}

            <div className="space-y-1.5">
              <Label htmlFor="email">Email</Label>
              <div className="relative">
                <Mail className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  id="email"
                  type="email"
                  autoComplete="username"
                  placeholder="you@organisation.com"
                  className="pl-9"
                  {...form.register("email")}
                />
              </div>
              {form.formState.errors.email && (
                <p className="text-xs text-destructive">{form.formState.errors.email.message}</p>
              )}
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="password">Password</Label>
              <div className="relative">
                <Lock className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  id="password"
                  type="password"
                  autoComplete="current-password"
                  placeholder="••••••••"
                  className="pl-9"
                  {...form.register("password")}
                />
              </div>
              {form.formState.errors.password && (
                <p className="text-xs text-destructive">{form.formState.errors.password.message}</p>
              )}
            </div>

            <Button type="submit" className="w-full" loading={form.formState.isSubmitting}>
              Sign in
            </Button>
          </form>

          <div className="space-y-2.5 rounded-lg border bg-card p-4">
            <div className="flex items-center justify-between">
              <p className="text-sm font-medium">Demo accounts</p>
              <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px]">
                {DEMO_PASSWORD}
              </code>
            </div>
            <p className="text-xs text-muted-foreground">
              Each role sees a different slice of the platform. Click one to fill the form.
            </p>
            <div className="grid gap-1.5">
              {DEMO_ACCOUNTS.map((account) => (
                <button
                  key={account.email}
                  type="button"
                  onClick={() => fillDemo(account.email)}
                  className="group flex items-center justify-between gap-3 rounded-md border px-3 py-2 text-left transition-colors hover:border-primary/40 hover:bg-accent"
                >
                  <span className="min-w-0">
                    <span className="block text-[13px] font-semibold tracking-[-0.01em]">{account.role}</span>
                    <span className="block truncate text-[11.5px] leading-snug text-muted-foreground">
                      {account.note}
                    </span>
                  </span>
                  <span className="shrink-0 font-mono text-[11px] tracking-tight text-muted-foreground group-hover:text-primary">
                    {account.email.split("@")[0]}
                  </span>
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
