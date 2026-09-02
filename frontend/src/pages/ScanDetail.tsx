import * as React from "react"
import { Link, useParams } from "react-router-dom"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import {
  ArrowLeft, CheckCircle2, ChevronRight, CircleDashed, Clock, GitMerge, Loader2,
  Radar, StopCircle, XCircle, Zap,
} from "lucide-react"
import { findingApi, scanApi } from "@/services/endpoints"
import { PageHeader } from "@/layouts/AppLayout"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge, SeverityBadge, StatusBadge } from "@/components/ui/badge"
import { ConfirmDialog } from "@/components/ui/confirm"
import { EmptyState, ErrorState, Progress, Skeleton, Tooltip } from "@/components/ui/misc"
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table"
import { errorMessage, useToast } from "@/components/ui/toast"
import { useScanProgress } from "@/hooks/useScanProgress"
import { cn, formatDate, titleCase } from "@/lib/utils"
import { useAuth } from "@/hooks/useAuth"

const RUN_ICONS: Record<string, { icon: React.ComponentType<{ className?: string }>; tone: string }> = {
  PENDING: { icon: CircleDashed, tone: "text-muted-foreground" },
  RUNNING: { icon: Loader2, tone: "text-primary animate-spin" },
  COMPLETED: { icon: CheckCircle2, tone: "text-success" },
  FAILED: { icon: XCircle, tone: "text-severity-critical" },
  SKIPPED: { icon: CircleDashed, tone: "text-muted-foreground" },
  UNAVAILABLE: { icon: CircleDashed, tone: "text-severity-medium" },
}

export default function ScanDetailPage() {
  const { id } = useParams()
  const scanId = Number(id)
  const { can } = useAuth()
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [cancelOpen, setCancelOpen] = React.useState(false)

  const { data: scan, isLoading, error, refetch } = useQuery({
    queryKey: ["scan", scanId],
    queryFn: () => scanApi.get(scanId),
    enabled: Number.isFinite(scanId),
    refetchInterval: (query) =>
      ["RUNNING", "QUEUED"].includes(query.state.data?.status ?? "") ? 2000 : false,
  })

  const isActive = ["RUNNING", "QUEUED"].includes(scan?.status ?? "")
  const { live, connected } = useScanProgress(scanId, isActive)

  const { data: findings } = useQuery({
    queryKey: ["findings", { scan_id: scanId }],
    queryFn: () => findingApi.list({ scan_id: scanId, page_size: 100 }),
    enabled: !!scan && scan.status === "COMPLETED",
  })

  const cancelMutation = useMutation({
    mutationFn: () => scanApi.cancel(scanId),
    onSuccess: () => {
      toast("success", "Scan cancelled")
      setCancelOpen(false)
      queryClient.invalidateQueries({ queryKey: ["scan", scanId] })
    },
    onError: (e) => toast("error", "Could not cancel the scan", errorMessage(e)),
  })

  if (isLoading) return <><Skeleton className="mb-4 h-9 w-64" /><Skeleton className="h-80" /></>
  if (error || !scan) return <Card><ErrorState error={error} onRetry={refetch} /></Card>

  // Live socket values take precedence while the scan is running.
  const progress = live?.progress ?? scan.progress
  const status = live?.status ?? scan.status
  const operation = live?.current_operation ?? scan.current_operation
  const findingsCount = live?.findings_count ?? scan.findings_count
  const runs = (live as any)?.scanner_runs ?? scan.scanner_runs

  return (
    <>
      <div className="mb-4 flex items-center gap-1.5 text-sm text-muted-foreground">
        <Link to="/scans" className="inline-flex items-center gap-1 hover:text-foreground">
          <ArrowLeft className="h-3.5 w-3.5" /> Scans
        </Link>
        <ChevronRight className="h-3.5 w-3.5" />
        <span className="font-mono text-xs">{scan.reference}</span>
      </div>

      <PageHeader
        title={scan.target_name ?? scan.reference}
        badge={
          <span className="flex items-center gap-1.5">
            <StatusBadge status={status} />
            <Badge variant="muted">{titleCase(scan.profile)}</Badge>
          </span>
        }
        description={<span className="font-mono text-xs">{scan.target_value}</span>}
        actions={
          can("scan:cancel") && ["RUNNING", "QUEUED"].includes(status) ? (
            <Button variant="destructive" onClick={() => setCancelOpen(true)}>
              <StopCircle /> Cancel scan
            </Button>
          ) : null
        }
      />

      {/* Live progress */}
      <Card className="mb-4">
        <CardContent className="space-y-4 p-5">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              {status === "RUNNING" ? (
                <Loader2 className="h-4 w-4 animate-spin text-primary" />
              ) : (
                <Radar className="h-4 w-4 text-muted-foreground" />
              )}
              <span className="text-sm font-medium">
                {status === "RUNNING" ? "Scan in progress" :
                 status === "QUEUED" ? "Queued" :
                 status === "COMPLETED" ? "Scan complete" : titleCase(status)}
              </span>
              {isActive && (
                <Tooltip label={connected ? "Live updates over WebSocket" : "Polling for updates"}>
                  <span className={cn("flex items-center gap-1 text-[11px]", connected ? "text-success" : "text-muted-foreground")}>
                    <span className={cn("h-1.5 w-1.5 rounded-full", connected ? "bg-success" : "bg-muted-foreground")} />
                    {connected ? "live" : "polling"}
                  </span>
                </Tooltip>
              )}
            </div>
            <span className="text-2xl font-bold tabular-nums">{progress}%</span>
          </div>

          <Progress
            value={progress}
            className="h-2.5"
            indicatorClassName={cn(
              status === "FAILED" && "bg-destructive",
              status === "COMPLETED" && "bg-success"
            )}
          />

          {operation && (
            <p className="text-sm text-muted-foreground">
              <span className="font-medium text-foreground">Current operation:</span> {operation}
            </p>
          )}

          <div className="grid gap-3 sm:grid-cols-4">
            {[
              { label: "Findings", value: findingsCount, icon: Zap },
              { label: "Raw results", value: scan.raw_findings_count, icon: Radar },
              { label: "Duplicates merged", value: scan.duplicates_merged, icon: GitMerge },
              {
                label: "Duration",
                value: scan.duration_seconds != null ? `${scan.duration_seconds.toFixed(1)}s` : "—",
                icon: Clock,
              },
            ].map((item) => (
              <div key={item.label} className="rounded-md bg-muted/50 p-3">
                <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                  {item.label}
                </p>
                <p className="text-lg font-semibold">{item.value}</p>
              </div>
            ))}
          </div>

          {scan.error_message && (
            <div className="rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm">
              <p className="font-medium text-destructive">Scan error</p>
              <p className="mt-0.5 text-muted-foreground">{scan.error_message}</p>
            </div>
          )}
        </CardContent>
      </Card>

      <div className="grid gap-4 lg:grid-cols-3">
        {/* Scanner runs */}
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Scanner execution</CardTitle>
            <CardDescription>
              Each adapter that participated, and what it contributed.
            </CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <ul className="divide-y">
              {runs.map((run: any) => {
                const style = RUN_ICONS[run.status] ?? RUN_ICONS.PENDING
                const Icon = style.icon
                return (
                  <li key={run.id ?? run.scanner} className="flex items-start gap-3 px-5 py-3">
                    <Icon className={cn("mt-0.5 h-4 w-4 shrink-0", style.tone)} />
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-sm font-medium">{run.scanner_label ?? run.scanner}</span>
                        <StatusBadge status={run.status === "UNAVAILABLE" ? "CANCELLED" : run.status} />
                        {run.raw_findings_count > 0 && (
                          <Badge variant="muted">{run.raw_findings_count} results</Badge>
                        )}
                      </div>
                      {run.error_message && (
                        <p className="mt-0.5 text-xs text-muted-foreground">{run.error_message}</p>
                      )}
                      {run.command_summary && (
                        <p className="mt-0.5 break-all font-mono text-[10px] text-muted-foreground">
                          {run.command_summary}
                        </p>
                      )}
                      <p className="mt-0.5 text-[11px] text-muted-foreground">
                        {run.tool_version ? `${run.tool_version} · ` : ""}
                        {run.duration_ms != null ? `${(run.duration_ms / 1000).toFixed(1)}s` : "—"}
                        {run.exit_code != null ? ` · exit ${run.exit_code}` : ""}
                      </p>
                    </div>
                  </li>
                )
              })}
            </ul>
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle>Scan details</CardTitle></CardHeader>
          <CardContent className="space-y-3 text-sm">
            {[
              ["Reference", scan.reference],
              ["Assessment", scan.assessment_name],
              ["Profile", titleCase(scan.profile)],
              ["Requested scanners", scan.requested_scanners.join(", ")],
              ["Runner", scan.task_runner ?? "—"],
              ["Started", formatDate(scan.started_at, true)],
              ["Completed", formatDate(scan.completed_at, true)],
              ["Started by", scan.created_by?.full_name ?? "—"],
            ].map(([label, value]) => (
              <div key={label as string} className="space-y-0.5">
                <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                  {label}
                </p>
                <p className="break-words">{value || "—"}</p>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {/* Findings produced */}
      {scan.status === "COMPLETED" && (
        <Card className="mt-4 overflow-hidden">
          <CardHeader>
            <CardTitle>Findings from this scan</CardTitle>
            <CardDescription>
              Normalized, correlated and scored automatically.
            </CardDescription>
          </CardHeader>
          {!findings || findings.items.length === 0 ? (
            <EmptyState
              icon={CheckCircle2}
              title="No findings produced"
              description="Nothing the enabled scanners check for was detected on this target."
            />
          ) : (
            <Table>
              <THead>
                <TR><TH>ID</TH><TH>Severity</TH><TH>Title</TH><TH>CVSS</TH><TH>CWE</TH><TH>Source</TH><TH>Status</TH></TR>
              </THead>
              <TBody>
                {findings.items.map((finding) => (
                  <TR key={finding.id}>
                    <TD>
                      <Link to={`/findings/${finding.id}`} className="font-mono text-xs text-primary hover:underline">
                        {finding.reference}
                      </Link>
                    </TD>
                    <TD><SeverityBadge severity={finding.severity} /></TD>
                    <TD>
                      <Link to={`/findings/${finding.id}`} className="line-clamp-1 max-w-md font-medium hover:text-primary">
                        {finding.title}
                      </Link>
                    </TD>
                    <TD className="font-mono text-sm">{finding.cvss_score?.toFixed(1) ?? "—"}</TD>
                    <TD className="text-xs">{finding.cwe_id ?? "—"}</TD>
                    <TD>
                      <Badge variant="muted" className="text-[10px]">{finding.primary_source}</Badge>
                      {finding.source_count > 1 && (
                        <span className="ml-1 text-[10px] text-primary">+{finding.source_count - 1}</span>
                      )}
                    </TD>
                    <TD><StatusBadge status={finding.status} /></TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          )}
        </Card>
      )}

      <ConfirmDialog
        open={cancelOpen}
        onOpenChange={setCancelOpen}
        title="Cancel this scan?"
        description="Scanners already running will stop at their next checkpoint. Findings produced so far are kept."
        confirmLabel="Cancel scan"
        loading={cancelMutation.isPending}
        onConfirm={() => cancelMutation.mutate()}
      />
    </>
  )
}
