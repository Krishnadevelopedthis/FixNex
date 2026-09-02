import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "@/lib/utils"
import { CRITICAL_PULSE } from "@/lib/motion"
import { SEVERITY_BADGE, SEVERITY_DOT, SLA_BADGE, SLA_LABEL, STATUS_BADGE } from "@/lib/severity"
import { titleCase } from "@/lib/utils"

const badgeVariants = cva(
  "inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-medium transition-colors whitespace-nowrap",
  {
    variants: {
      variant: {
        default: "bg-primary/10 text-primary ring-1 ring-inset ring-primary/25",
        secondary: "bg-secondary text-secondary-foreground",
        outline: "text-foreground ring-1 ring-inset ring-border",
        muted: "bg-muted text-muted-foreground ring-1 ring-inset ring-border",
        destructive: "bg-destructive/10 text-destructive ring-1 ring-inset ring-destructive/25",
      },
    },
    defaultVariants: { variant: "default" },
  }
)

export interface BadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>, VariantProps<typeof badgeVariants> {}

export function Badge({ className, variant, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ variant }), className)} {...props} />
}

export function SeverityBadge({ severity, showDot = true, pulse = false, className }: {
  severity?: string | null
  showDot?: boolean
  /** Opt in to the ambient CRITICAL pulse. Off by default so dense tables stay still. */
  pulse?: boolean
  className?: string
}) {
  const key = severity ?? "INFORMATIONAL"
  return (
    <span className={cn(
      badgeVariants({}),
      SEVERITY_BADGE[key] ?? SEVERITY_BADGE.INFORMATIONAL,
      "uppercase tracking-wide",
      pulse && key === "CRITICAL" && CRITICAL_PULSE,
      className,
    )}>
      {showDot && <span className={cn("sev-dot", SEVERITY_DOT[key])} />}
      {key === "INFORMATIONAL" ? "Info" : titleCase(key)}
    </span>
  )
}

export function StatusBadge({ status, className }: { status?: string | null; className?: string }) {
  const key = status ?? "DISCOVERED"
  return (
    <span className={cn(badgeVariants({}), STATUS_BADGE[key] ?? STATUS_BADGE.DISCOVERED, className)}>
      {titleCase(key)}
    </span>
  )
}

export function SlaBadge({ sla, className }: {
  sla?: { status: string; hours_remaining?: number | null } | null
  className?: string
}) {
  if (!sla) return <span className="text-xs text-muted-foreground">—</span>
  const hours = sla.hours_remaining
  const detail =
    hours == null ? "" :
    sla.status === "OVERDUE" ? ` ${Math.abs(Math.round(hours))}h over` :
    sla.status === "ON_TRACK" || sla.status === "DUE_SOON" ? ` ${Math.round(hours)}h left` : ""
  return (
    <span className={cn(badgeVariants({}), SLA_BADGE[sla.status] ?? SLA_BADGE.NOT_APPLICABLE, className)}>
      {SLA_LABEL[sla.status] ?? titleCase(sla.status)}{detail}
    </span>
  )
}

/** Marks seeded demonstration content so it is never mistaken for a real scan result. */
export function DemoBadge({ className }: { className?: string }) {
  return (
    <span className={cn(badgeVariants({ variant: "outline" }), "border-dashed uppercase tracking-wider text-[10px] text-muted-foreground", className)}>
      Demo data
    </span>
  )
}

export { badgeVariants }
