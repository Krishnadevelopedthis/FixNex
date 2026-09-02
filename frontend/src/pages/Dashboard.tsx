import { Link } from "react-router-dom"
import { useQuery } from "@tanstack/react-query"
import {
  Activity, AlertTriangle, Bug, CheckCircle2, Clock, FolderKanban, Radar,
  Server, ShieldAlert, TrendingUp, Wrench,
} from "lucide-react"
import { dashboardApi } from "@/services/endpoints"
import { PageHeader } from "@/layouts/AppLayout"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge, StatusBadge } from "@/components/ui/badge"
import { EmptyState, ErrorState, Progress, Skeleton } from "@/components/ui/misc"
import { CvssHistogram, RiskDonutChart, RiskHeatmap, SeverityBarChart, TrendChart } from "@/components/charts"
import { AssetHeatmapCard, PostureCard } from "@/components/posture"
import { cn, relativeTime, titleCase } from "@/lib/utils"
import { SEVERITY_DOT } from "@/lib/severity"
import { useAuth } from "@/hooks/useAuth"
import { AnimatedNumber } from "@/components/animated-number"

function StatCard({ label, value, icon: Icon, tone = "default", sub, to }: {
  label: string
  value: React.ReactNode
  icon: React.ComponentType<{ className?: string }>
  tone?: "default" | "critical" | "high" | "success" | "warning"
  sub?: React.ReactNode
  to?: string
}) {
  const tones = {
    default: "bg-primary/10 text-primary",
    critical: "bg-severity-critical/12 text-severity-critical",
    high: "bg-severity-high/12 text-severity-high",
    success: "bg-success/12 text-success",
    warning: "bg-warning/12 text-warning",
  }
  const body = (
    <Card interactive={!!to}>
      <CardContent className="flex items-center gap-4 p-5">
        <div className={cn("flex h-10 w-10 shrink-0 items-center justify-center rounded-lg", tones[tone])}>
          <Icon className="h-5 w-5" />
        </div>
        <div className="min-w-0">
          <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{label}</p>
          <p className="text-2xl font-bold leading-tight tabular-nums">
            {typeof value === "number" ? <AnimatedNumber value={value} /> : value}
          </p>
          {sub && <p className="mt-0.5 text-xs text-muted-foreground">{sub}</p>}
        </div>
      </CardContent>
    </Card>
  )
  return to ? <Link to={to}>{body}</Link> : body
}

export default function DashboardPage() {
  const { user } = useAuth()
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["dashboard"],
    queryFn: dashboardApi.get,
    refetchInterval: 30_000,
  })

  if (isLoading) {
    return (
      <>
        <PageHeader title="Dashboard" description="Loading security posture…" />
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-24" />)}
        </div>
        <div className="mt-4 grid gap-4 lg:grid-cols-3">
          {Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-72" />)}
        </div>
      </>
    )
  }

  if (error || !data) {
    return (
      <>
        <PageHeader title="Dashboard" />
        <Card><ErrorState error={error} onRetry={refetch} /></Card>
      </>
    )
  }

  const { assessments, findings, remediation, scans } = data
  const openFindings = findings.total - findings.closed - findings.false_positive

  return (
    <>
      <PageHeader
        title={`Welcome back, ${user?.full_name?.split(" ")[0] ?? "there"}`}
        description="Security posture across every assessment you have access to."
        badge={data.demo_mode ? <Badge variant="outline" className="border-dashed">Demo mode</Badge> : null}
      />

      {/* Headline counters */}
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Assessments" value={assessments.total} icon={FolderKanban} to="/assessments"
          sub={`${assessments.active} active · ${assessments.completed} completed`}
        />
        <StatCard
          label="Open findings" value={openFindings} icon={Bug} tone="high" to="/findings"
          sub={`${findings.total} total · ${findings.false_positive} false positive`}
        />
        <StatCard
          label="Critical & high" value={findings.critical + findings.high} icon={ShieldAlert} tone="critical"
          to="/findings" sub={`${findings.critical} critical · ${findings.high} high`}
        />
        <StatCard
          label="Overdue SLA" value={remediation.overdue} icon={Clock}
          tone={remediation.overdue > 0 ? "critical" : "success"} to="/remediation"
          sub={`${remediation.due_soon} due soon`}
        />
      </div>

      {(data.posture || data.asset_heatmap) && (
        <div className="mt-4 grid gap-4 lg:grid-cols-2">
          {data.posture && <PostureCard data={data.posture} />}
          {data.asset_heatmap && <AssetHeatmapCard data={data.asset_heatmap} />}
        </div>
      )}

      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        {/* Severity */}
        <Card>
          <CardHeader>
            <CardTitle>Findings by severity</CardTitle>
            <CardDescription>Current open and closed findings</CardDescription>
          </CardHeader>
          <CardContent>
            <SeverityBarChart data={data.severity_distribution} />
          </CardContent>
        </Card>

        {/* Contextual risk */}
        <Card>
          <CardHeader>
            <CardTitle>Contextual risk distribution</CardTitle>
            <CardDescription>FixNex risk score, not raw CVSS</CardDescription>
          </CardHeader>
          <CardContent>
            <RiskDonutChart data={data.risk_distribution} />
          </CardContent>
        </Card>

        {/* Remediation progress */}
        <Card>
          <CardHeader>
            <CardTitle>Remediation progress</CardTitle>
            <CardDescription>Confirmed findings moving to closure</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <div className="mb-1.5 flex items-baseline justify-between">
                <span className="text-sm text-muted-foreground">Resolved</span>
                <span className="text-2xl font-bold tabular-nums">
                  <AnimatedNumber value={remediation.progress_percent} suffix="%" />
                </span>
              </div>
              <Progress
                value={remediation.progress_percent}
                indicatorClassName="bg-success"
              />
            </div>
            <div className="grid grid-cols-2 gap-2 text-sm">
              {[
                { label: "Open", value: remediation.open, tone: "text-muted-foreground" },
                { label: "In progress", value: remediation.in_progress, tone: "text-primary" },
                { label: "Ready for retest", value: remediation.ready_for_retest, tone: "text-severity-medium" },
                { label: "Resolved", value: remediation.resolved, tone: "text-success" },
                { label: "Reopened", value: remediation.reopened, tone: "text-severity-critical" },
                { label: "Overdue", value: remediation.overdue, tone: "text-severity-critical" },
              ].map((row) => (
                <div key={row.label} className="flex items-center justify-between rounded-md bg-muted/50 px-2.5 py-1.5">
                  <span className="text-xs text-muted-foreground">{row.label}</span>
                  <span className={cn("text-sm font-semibold", row.tone)}>{row.value}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Discovery vs. closure</CardTitle>
            <CardDescription>Findings raised and closed over the last 14 days</CardDescription>
          </CardHeader>
          <CardContent>
            <TrendChart data={data.trend} />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Risk heat map</CardTitle>
            <CardDescription>Impact against likelihood</CardDescription>
          </CardHeader>
          <CardContent>
            <RiskHeatmap data={data.risk_heatmap} />
          </CardContent>
        </Card>
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>CVSS distribution</CardTitle>
            <CardDescription>Base scores across all findings</CardDescription>
          </CardHeader>
          <CardContent>
            <CvssHistogram data={data.cvss_distribution} />
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex-row items-center justify-between space-y-0">
            <div className="space-y-1">
              <CardTitle>Top risky assets</CardTitle>
              <CardDescription>Ranked by open findings and severity</CardDescription>
            </div>
            <TrendingUp className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent className="p-0">
            {data.top_risky_assets.length === 0 ? (
              <EmptyState icon={Server} title="No assets with open findings" />
            ) : (
              <ul className="divide-y">
                {data.top_risky_assets.slice(0, 6).map((asset, index) => (
                  <li key={`${asset.target_id}-${index}`} className="flex items-center gap-3 px-5 py-2.5">
                    <span className="w-4 shrink-0 text-xs font-medium text-muted-foreground">{index + 1}</span>
                    <span className={cn("sev-dot", SEVERITY_DOT[asset.max_severity ?? "INFORMATIONAL"])} />
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm font-medium">{asset.name}</p>
                      {asset.value && (
                        <p className="truncate font-mono text-[11px] text-muted-foreground">{asset.value}</p>
                      )}
                    </div>
                    <div className="shrink-0 text-right">
                      <p className="text-sm font-semibold">{asset.open_findings}</p>
                      <p className="text-[10px] uppercase tracking-wide text-muted-foreground">open</p>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        {/* Scanner activity */}
        <Card>
          <CardHeader className="flex-row items-center justify-between space-y-0">
            <div className="space-y-1">
              <CardTitle>Recent scans</CardTitle>
              <CardDescription>
                {scans.running} running · {scans.queued} queued · {scans.failed} failed
              </CardDescription>
            </div>
            <Link to="/scans" className="text-xs font-medium text-primary hover:underline">View all</Link>
          </CardHeader>
          <CardContent className="p-0">
            {data.recent_scans.length === 0 ? (
              <EmptyState icon={Radar} title="No scans yet" description="Start a scan from an authorized target." />
            ) : (
              <ul className="divide-y">
                {data.recent_scans.slice(0, 6).map((scan) => (
                  <li key={scan.id}>
                    <Link to={`/scans/${scan.id}`} className="flex items-center gap-3 px-5 py-2.5 hover:bg-accent/50">
                      <Radar className="h-4 w-4 shrink-0 text-muted-foreground" />
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-sm font-medium">
                          {scan.target_name ?? scan.reference}
                        </p>
                        <p className="text-[11px] text-muted-foreground">
                          {titleCase(scan.profile)} · {relativeTime(scan.created_at)}
                        </p>
                      </div>
                      {scan.status === "RUNNING" ? (
                        <div className="w-20 shrink-0">
                          <Progress value={scan.progress} className="h-1.5" />
                        </div>
                      ) : (
                        <Badge variant="muted" className="shrink-0">{scan.findings_count} found</Badge>
                      )}
                      <StatusBadge status={scan.status} className="shrink-0" />
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        {/* Audit activity */}
        <Card>
          <CardHeader className="flex-row items-center justify-between space-y-0">
            <div className="space-y-1">
              <CardTitle>Recent activity</CardTitle>
              <CardDescription>From the append-only audit trail</CardDescription>
            </div>
            <Link to="/audit" className="text-xs font-medium text-primary hover:underline">View all</Link>
          </CardHeader>
          <CardContent className="p-0">
            {data.recent_activity.length === 0 ? (
              <EmptyState icon={Activity} title="No recorded activity yet" />
            ) : (
              <ul className="divide-y">
                {data.recent_activity.slice(0, 7).map((item) => (
                  <li key={item.id} className="flex items-start gap-3 px-5 py-2.5">
                    <ActivityIcon action={item.action} />
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm">{item.description ?? titleCase(item.action)}</p>
                      <p className="text-[11px] text-muted-foreground">
                        {item.actor ?? "System"} · {relativeTime(item.created_at)}
                      </p>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>
    </>
  )
}

function ActivityIcon({ action }: { action: string }) {
  const map: Record<string, { icon: React.ComponentType<{ className?: string }>; tone: string }> = {
    scan: { icon: Radar, tone: "text-primary" },
    finding: { icon: Bug, tone: "text-severity-high" },
    evidence: { icon: CheckCircle2, tone: "text-success" },
    remediation: { icon: Wrench, tone: "text-primary" },
    retest: { icon: CheckCircle2, tone: "text-success" },
    scope: { icon: AlertTriangle, tone: "text-severity-critical" },
    auth: { icon: Activity, tone: "text-muted-foreground" },
  }
  const prefix = action.split(".")[0]
  const { icon: Icon, tone } = map[prefix] ?? { icon: Activity, tone: "text-muted-foreground" }
  return <Icon className={cn("mt-0.5 h-4 w-4 shrink-0", tone)} />
}
