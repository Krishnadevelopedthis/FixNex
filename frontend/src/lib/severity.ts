/** Single source of truth for how severity, status and SLA are coloured. */

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL"

export const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]

export const SEVERITY_ORDER: Record<string, number> = {
  CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFORMATIONAL: 1,
}

/** Chart/dot fills, resolved from the CSS custom properties so themes track. */
export const SEVERITY_VAR: Record<string, string> = {
  CRITICAL: "hsl(var(--severity-critical))",
  HIGH: "hsl(var(--severity-high))",
  MEDIUM: "hsl(var(--severity-medium))",
  LOW: "hsl(var(--severity-low))",
  INFORMATIONAL: "hsl(var(--severity-info))",
}

export const SEVERITY_BADGE: Record<string, string> = {
  CRITICAL: "bg-severity-critical/12 text-severity-critical ring-1 ring-inset ring-severity-critical/30",
  HIGH: "bg-severity-high/12 text-severity-high ring-1 ring-inset ring-severity-high/30",
  MEDIUM: "bg-severity-medium/14 text-severity-medium ring-1 ring-inset ring-severity-medium/30",
  LOW: "bg-severity-low/12 text-severity-low ring-1 ring-inset ring-severity-low/30",
  INFORMATIONAL: "bg-severity-info/12 text-severity-info ring-1 ring-inset ring-severity-info/30",
}

export const SEVERITY_DOT: Record<string, string> = {
  CRITICAL: "bg-severity-critical",
  HIGH: "bg-severity-high",
  MEDIUM: "bg-severity-medium",
  LOW: "bg-severity-low",
  INFORMATIONAL: "bg-severity-info",
}

export const STATUS_BADGE: Record<string, string> = {
  DISCOVERED: "bg-muted text-muted-foreground ring-1 ring-inset ring-border",
  NEEDS_VERIFICATION: "bg-severity-medium/14 text-severity-medium ring-1 ring-inset ring-severity-medium/30",
  CONFIRMED: "bg-severity-high/12 text-severity-high ring-1 ring-inset ring-severity-high/30",
  FALSE_POSITIVE: "bg-muted text-muted-foreground ring-1 ring-inset ring-border line-through decoration-1",
  TRIAGED: "bg-primary/10 text-primary ring-1 ring-inset ring-primary/25",
  REMEDIATION: "bg-primary/10 text-primary ring-1 ring-inset ring-primary/25",
  RETEST: "bg-severity-medium/14 text-severity-medium ring-1 ring-inset ring-severity-medium/30",
  CLOSED: "bg-success/12 text-success ring-1 ring-inset ring-success/30",
  // remediation statuses
  OPEN: "bg-muted text-muted-foreground ring-1 ring-inset ring-border",
  IN_PROGRESS: "bg-primary/10 text-primary ring-1 ring-inset ring-primary/25",
  READY_FOR_RETEST: "bg-severity-medium/14 text-severity-medium ring-1 ring-inset ring-severity-medium/30",
  RETESTING: "bg-severity-medium/14 text-severity-medium ring-1 ring-inset ring-severity-medium/30",
  RESOLVED: "bg-success/12 text-success ring-1 ring-inset ring-success/30",
  REOPENED: "bg-severity-critical/12 text-severity-critical ring-1 ring-inset ring-severity-critical/30",
  // scan statuses
  QUEUED: "bg-muted text-muted-foreground ring-1 ring-inset ring-border",
  RUNNING: "bg-primary/10 text-primary ring-1 ring-inset ring-primary/25",
  COMPLETED: "bg-success/12 text-success ring-1 ring-inset ring-success/30",
  FAILED: "bg-severity-critical/12 text-severity-critical ring-1 ring-inset ring-severity-critical/30",
  CANCELLED: "bg-muted text-muted-foreground ring-1 ring-inset ring-border",
  // assessment statuses
  DRAFT: "bg-muted text-muted-foreground ring-1 ring-inset ring-border",
  ACTIVE: "bg-success/12 text-success ring-1 ring-inset ring-success/30",
  PAUSED: "bg-severity-medium/14 text-severity-medium ring-1 ring-inset ring-severity-medium/30",
  ARCHIVED: "bg-muted text-muted-foreground ring-1 ring-inset ring-border",
  // target statuses
  AUTHORIZED: "bg-success/12 text-success ring-1 ring-inset ring-success/30",
  PENDING_AUTHORIZATION: "bg-severity-medium/14 text-severity-medium ring-1 ring-inset ring-severity-medium/30",
  DISABLED: "bg-muted text-muted-foreground ring-1 ring-inset ring-border",
}

export const SLA_BADGE: Record<string, string> = {
  ON_TRACK: "bg-success/12 text-success ring-1 ring-inset ring-success/30",
  DUE_SOON: "bg-severity-medium/14 text-severity-medium ring-1 ring-inset ring-severity-medium/30",
  OVERDUE: "bg-severity-critical/12 text-severity-critical ring-1 ring-inset ring-severity-critical/30",
  MET: "bg-success/12 text-success ring-1 ring-inset ring-success/30",
  BREACHED: "bg-severity-critical/12 text-severity-critical ring-1 ring-inset ring-severity-critical/30",
  NOT_APPLICABLE: "bg-muted text-muted-foreground ring-1 ring-inset ring-border",
}

export const SLA_LABEL: Record<string, string> = {
  ON_TRACK: "On track", DUE_SOON: "Due soon", OVERDUE: "Overdue",
  MET: "Met", BREACHED: "Breached", NOT_APPLICABLE: "No SLA",
}

export function cvssBand(score?: number | null): Severity {
  if (score == null) return "INFORMATIONAL"
  if (score >= 9) return "CRITICAL"
  if (score >= 7) return "HIGH"
  if (score >= 4) return "MEDIUM"
  if (score > 0) return "LOW"
  return "INFORMATIONAL"
}
