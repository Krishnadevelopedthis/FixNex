import * as React from "react"
import { Link } from "react-router-dom"
import { useQuery } from "@tanstack/react-query"
import { AlertTriangle, CheckCircle2, Clock, Wrench } from "lucide-react"
import { remediationApi } from "@/services/endpoints"
import { PageHeader } from "@/layouts/AppLayout"
import { Card, CardContent } from "@/components/ui/card"
import { Badge, SeverityBadge, SlaBadge, StatusBadge } from "@/components/ui/badge"
import { EmptyState, ErrorState, TableSkeleton } from "@/components/ui/misc"
import { Pagination, Table, TBody, TD, TH, THead, TR } from "@/components/ui/table"
import { cn, relativeTime } from "@/lib/utils"
import { useAuth } from "@/hooks/useAuth"

const FILTERS = [
  { key: "all", label: "All" },
  { key: "OPEN", label: "Open" },
  { key: "IN_PROGRESS", label: "In progress" },
  { key: "READY_FOR_RETEST", label: "Ready for retest" },
  { key: "REOPENED", label: "Reopened" },
  { key: "overdue", label: "Overdue" },
]

export default function RemediationPage() {
  const { user } = useAuth()
  const [filter, setFilter] = React.useState("all")
  const [page, setPage] = React.useState(1)

  const params = React.useMemo(() => {
    const q: Record<string, unknown> = { page, page_size: 25 }
    if (filter === "overdue") q.sla_status = "OVERDUE"
    else if (filter !== "all") q.remediation_status = filter
    return q
  }, [filter, page])

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["remediation", params],
    queryFn: () => remediationApi.list(params),
  })

  const overdueCount = data?.items.filter((f) => f.sla?.status === "OVERDUE").length ?? 0

  return (
    <>
      <PageHeader
        title="Remediation"
        description={
          user?.role === "DEVELOPER"
            ? "Findings assigned to you, with their SLA deadlines."
            : "Confirmed findings in remediation across all assessments."
        }
      />

      {overdueCount > 0 && (
        <Card className="mb-4 border-severity-critical/30 bg-severity-critical/5">
          <CardContent className="flex items-center gap-3 p-4">
            <AlertTriangle className="h-4 w-4 shrink-0 text-severity-critical" />
            <p className="text-sm">
              <span className="font-medium">{overdueCount}</span> finding{overdueCount === 1 ? " is" : "s are"} past
              the remediation SLA on this page.
            </p>
          </CardContent>
        </Card>
      )}

      <div className="mb-4 flex flex-wrap gap-1.5">
        {FILTERS.map((f) => (
          <button
            key={f.key}
            onClick={() => { setFilter(f.key); setPage(1) }}
            className={cn(
              "rounded-md px-3 py-1.5 text-sm font-medium ring-1 ring-inset transition-colors",
              filter === f.key
                ? "bg-primary/10 text-primary ring-primary/30"
                : "text-muted-foreground ring-border hover:bg-accent hover:text-foreground"
            )}
          >
            {f.label}
          </button>
        ))}
      </div>

      <Card className="overflow-hidden">
        {isLoading ? (
          <TableSkeleton rows={6} cols={7} />
        ) : error ? (
          <ErrorState error={error} onRetry={refetch} />
        ) : data && data.items.length === 0 ? (
          <EmptyState
            icon={filter === "all" ? Wrench : CheckCircle2}
            title={filter === "all" ? "Nothing in remediation" : "Nothing matches this filter"}
            description={
              user?.role === "DEVELOPER"
                ? "Findings assigned to you will appear here with their deadlines."
                : "Confirmed findings appear here once they are assigned to a developer."
            }
          />
        ) : (
          <>
            <Table>
              <THead>
                <TR>
                  <TH>ID</TH><TH>Severity</TH><TH>Finding</TH><TH>Priority</TH>
                  <TH>Status</TH><TH>Assigned to</TH><TH>SLA</TH><TH>Updated</TH>
                </TR>
              </THead>
              <TBody>
                {data?.items.map((finding) => (
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
                      {finding.target_name && (
                        <p className="text-[11px] text-muted-foreground">{finding.target_name}</p>
                      )}
                    </TD>
                    <TD>{finding.priority ? <Badge variant="muted">{finding.priority}</Badge> : "—"}</TD>
                    <TD><StatusBadge status={finding.status} /></TD>
                    <TD className="text-xs">{finding.assigned_to?.full_name ?? "Unassigned"}</TD>
                    <TD>
                      <div className="flex flex-col gap-0.5">
                        <SlaBadge sla={finding.sla} />
                        {finding.sla?.due_at && (
                          <span className="inline-flex items-center gap-1 text-[10px] text-muted-foreground">
                            <Clock className="h-2.5 w-2.5" /> {relativeTime(finding.sla.due_at)}
                          </span>
                        )}
                      </div>
                    </TD>
                    <TD className="whitespace-nowrap text-xs text-muted-foreground">
                      {relativeTime(finding.updated_at)}
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
            {data && (
              <Pagination page={data.page} pages={data.pages} total={data.total} pageSize={data.page_size} onPage={setPage} />
            )}
          </>
        )}
      </Card>
    </>
  )
}
