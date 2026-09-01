import {
  AlertTriangle, CheckCircle2, FileUp, GitMerge, Link2, MessageSquare, Plus,
  RefreshCw, ShieldCheck, SlidersHorizontal, UserPlus, Wrench, XCircle,
} from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { cn, formatDate, relativeTime, titleCase } from "@/lib/utils"
import type { FindingHistoryEntry } from "@/types"

const EVENT_STYLES: Record<string, { icon: React.ComponentType<{ className?: string }>; tone: string; label: string }> = {
  CREATED: { icon: Plus, tone: "bg-muted text-muted-foreground", label: "Discovered" },
  STATUS_CHANGED: { icon: RefreshCw, tone: "bg-muted text-muted-foreground", label: "Status changed" },
  VERIFIED: { icon: ShieldCheck, tone: "bg-severity-high/15 text-severity-high", label: "Verified" },
  FALSE_POSITIVE: { icon: XCircle, tone: "bg-muted text-muted-foreground", label: "False positive" },
  SCORED: { icon: SlidersHorizontal, tone: "bg-primary/15 text-primary", label: "Rescored" },
  TRIAGED: { icon: SlidersHorizontal, tone: "bg-primary/15 text-primary", label: "Triaged" },
  ASSIGNED: { icon: UserPlus, tone: "bg-primary/15 text-primary", label: "Assigned" },
  EVIDENCE_ADDED: { icon: FileUp, tone: "bg-success/15 text-success", label: "Evidence added" },
  COMMENT: { icon: MessageSquare, tone: "bg-muted text-muted-foreground", label: "Comment" },
  REMEDIATION_UPDATED: { icon: Wrench, tone: "bg-primary/15 text-primary", label: "Remediation updated" },
  RETEST_PERFORMED: { icon: CheckCircle2, tone: "bg-success/15 text-success", label: "Retest performed" },
  REOPENED: { icon: AlertTriangle, tone: "bg-severity-critical/15 text-severity-critical", label: "Reopened" },
  CLOSED: { icon: CheckCircle2, tone: "bg-success/15 text-success", label: "Closed" },
  ENRICHED: { icon: Link2, tone: "bg-muted text-muted-foreground", label: "Enriched" },
  CORRELATED: { icon: GitMerge, tone: "bg-primary/15 text-primary", label: "Correlated" },
}

/** Vertical status timeline for a finding's full history. */
export function FindingTimeline({ history }: { history: FindingHistoryEntry[] }) {
  if (!history.length) {
    return <p className="text-sm text-muted-foreground">No recorded history yet.</p>
  }

  return (
    <ol className="relative space-y-4 pl-1">
      {history.map((entry, index) => {
        const style = EVENT_STYLES[entry.event_type] ?? {
          icon: RefreshCw, tone: "bg-muted text-muted-foreground", label: titleCase(entry.event_type),
        }
        const Icon = style.icon
        const isLast = index === history.length - 1
        return (
          <li key={entry.id} className="relative flex gap-3">
            {!isLast && <span className="absolute left-[15px] top-8 h-[calc(100%-8px)] w-px bg-border" />}
            <span className={cn("z-10 flex h-8 w-8 shrink-0 items-center justify-center rounded-full", style.tone)}>
              <Icon className="h-4 w-4" />
            </span>
            <div className="min-w-0 flex-1 pb-1">
              <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                <span className="text-sm font-medium">{style.label}</span>
                {entry.from_status && entry.to_status && (
                  <span className="inline-flex items-center gap-1 text-[11px] text-muted-foreground">
                    <Badge variant="muted" className="text-[10px]">{titleCase(entry.from_status)}</Badge>
                    →
                    <Badge variant="muted" className="text-[10px]">{titleCase(entry.to_status)}</Badge>
                  </span>
                )}
                <span className="text-[11px] text-muted-foreground" title={formatDate(entry.created_at, true)}>
                  {relativeTime(entry.created_at)}
                </span>
              </div>
              {entry.note && (
                <p className="mt-0.5 whitespace-pre-wrap text-sm text-muted-foreground">{entry.note}</p>
              )}
              {entry.actor_name && (
                <p className="mt-0.5 text-[11px] text-muted-foreground">by {entry.actor_name}</p>
              )}
            </div>
          </li>
        )
      })}
    </ol>
  )
}
