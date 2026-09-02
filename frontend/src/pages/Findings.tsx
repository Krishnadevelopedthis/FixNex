import * as React from "react"
import { Link, useSearchParams } from "react-router-dom"
import { useQuery } from "@tanstack/react-query"
import { Bug, Filter, Search, X } from "lucide-react"
import { assessmentApi, findingApi, scanApi, userApi } from "@/services/endpoints"
import { PageHeader } from "@/layouts/AppLayout"
import { Card } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Badge, DemoBadge, SeverityBadge, SlaBadge, StatusBadge } from "@/components/ui/badge"
import { EmptyState, ErrorState, TableSkeleton, Tooltip } from "@/components/ui/misc"
import { MotionTR, Pagination, SortableTH, Table, TBody, TD, TH, THead, TR } from "@/components/ui/table"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { SEVERITIES } from "@/lib/severity"
import { cn, relativeTime, titleCase } from "@/lib/utils"
import { NewFindingDialog } from "@/components/finding-dialogs"
import { useEnterOnce } from "@/lib/motion"
import { useAuth } from "@/hooks/useAuth"

const STATUSES = [
  "DISCOVERED", "NEEDS_VERIFICATION", "CONFIRMED", "FALSE_POSITIVE",
  "TRIAGED", "REMEDIATION", "RETEST", "CLOSED",
]

const ALL = "__all__"

/** Multi-select filter rendered as a row of toggle chips. */
function ChipFilter({ label, options, selected, onChange, renderOption }: {
  label: string
  options: string[]
  selected: string[]
  onChange: (next: string[]) => void
  renderOption?: (value: string) => React.ReactNode
}) {
  function toggle(value: string) {
    onChange(selected.includes(value) ? selected.filter((v) => v !== value) : [...selected, value])
  }
  return (
    <div className="space-y-1.5">
      <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">{label}</p>
      <div className="flex flex-wrap gap-1.5">
        {options.map((option) => (
          <button
            key={option}
            onClick={() => toggle(option)}
            className={cn(
              "rounded-md px-2 py-1 text-xs font-medium ring-1 ring-inset transition-colors",
              selected.includes(option)
                ? "bg-primary/10 text-primary ring-primary/30"
                : "text-muted-foreground ring-border hover:bg-accent hover:text-foreground"
            )}
          >
            {renderOption ? renderOption(option) : titleCase(option)}
          </button>
        ))}
      </div>
    </div>
  )
}

export default function FindingsPage() {
  const { can } = useAuth()
  const [params, setParams] = useSearchParams()

  const [search, setSearch] = React.useState(params.get("search") ?? "")
  const [debounced, setDebounced] = React.useState(search)
  const [severity, setSeverity] = React.useState<string[]>(params.getAll("severity"))
  const [status, setStatus] = React.useState<string[]>(params.getAll("status"))
  const [source, setSource] = React.useState<string[]>([])
  const [assessmentId, setAssessmentId] = React.useState(params.get("assessment_id") ?? ALL)
  const [assignedTo, setAssignedTo] = React.useState(ALL)
  const [slaStatus, setSlaStatus] = React.useState(params.get("sla_status") ?? ALL)
  const [showFilters, setShowFilters] = React.useState(false)
  const [page, setPage] = React.useState(1)
  const [sort, setSort] = React.useState<{ by: string; order: "asc" | "desc" }>({
    by: "severity", order: "desc",
  })
  const [newOpen, setNewOpen] = React.useState(false)

  React.useEffect(() => {
    const timer = setTimeout(() => { setDebounced(search); setPage(1) }, 300)
    return () => clearTimeout(timer)
  }, [search])

  const { data: assessments } = useQuery({
    queryKey: ["assessments", "picker"],
    queryFn: () => assessmentApi.list({ page_size: 100 }),
  })
  const { data: scanners } = useQuery({ queryKey: ["scanners"], queryFn: scanApi.scanners })
  const { data: users } = useQuery({
    queryKey: ["users", "picker"],
    queryFn: () => userApi.list(false),
    enabled: can("user:view") || can("finding:assign"),
  })

  const query = React.useMemo(() => {
    const q: Record<string, unknown> = {
      page, page_size: 25, sort_by: sort.by, order: sort.order,
    }
    if (debounced) q.search = debounced
    if (severity.length) q.severity = severity
    if (status.length) q.status = status
    if (source.length) q.source = source
    if (assessmentId !== ALL) q.assessment_id = Number(assessmentId)
    if (assignedTo !== ALL) q.assigned_to_id = Number(assignedTo)
    if (slaStatus !== ALL) q.sla_status = slaStatus
    return q
  }, [page, sort, debounced, severity, status, source, assessmentId, assignedTo, slaStatus])

  const { data, isLoading, error, refetch, isFetching } = useQuery({
    queryKey: ["findings", query],
    queryFn: () => findingApi.list(query),
  })

  // Stagger the rows in on the first populated render only; a refetch that
  // returns the same rows must not replay the cascade under the reader.
  const enterRows = useEnterOnce(!!data?.items.length)

  // Keep the URL shareable as filters change.
  React.useEffect(() => {
    const next = new URLSearchParams()
    if (debounced) next.set("search", debounced)
    severity.forEach((s) => next.append("severity", s))
    status.forEach((s) => next.append("status", s))
    if (assessmentId !== ALL) next.set("assessment_id", assessmentId)
    if (slaStatus !== ALL) next.set("sla_status", slaStatus)
    setParams(next, { replace: true })
  }, [debounced, severity, status, assessmentId, slaStatus, setParams])

  const activeFilters =
    severity.length + status.length + source.length +
    (assessmentId !== ALL ? 1 : 0) + (assignedTo !== ALL ? 1 : 0) + (slaStatus !== ALL ? 1 : 0)

  function clearFilters() {
    setSeverity([]); setStatus([]); setSource([])
    setAssessmentId(ALL); setAssignedTo(ALL); setSlaStatus(ALL); setPage(1)
  }

  function toggleSort(field: string) {
    setSort((prev) =>
      prev.by === field
        ? { by: field, order: prev.order === "asc" ? "desc" : "asc" }
        : { by: field, order: "desc" }
    )
    setPage(1)
  }

  return (
    <>
      <PageHeader
        title="Findings"
        description="Every normalized finding across the assessments you can access."
        actions={
          <>
            <Button variant="outline" onClick={() => setShowFilters((v) => !v)}>
              <Filter />
              Filters
              {activeFilters > 0 && (
                <Badge className="ml-1 px-1.5 py-0">{activeFilters}</Badge>
              )}
            </Button>
            {can("finding:create") && (
              <Button onClick={() => setNewOpen(true)}>
                <Bug />
                Raise finding
              </Button>
            )}
          </>
        }
      />

      <Card className="mb-4 p-4">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
          <div className="relative flex-1">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by title, endpoint, CWE or CVE…"
              className="pl-9"
            />
            {search && (
              <button
                onClick={() => setSearch("")}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 rounded p-0.5 text-muted-foreground hover:text-foreground"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            )}
          </div>
          <Select value={assessmentId} onValueChange={(v) => { setAssessmentId(v); setPage(1) }}>
            <SelectTrigger className="sm:w-64"><SelectValue placeholder="All assessments" /></SelectTrigger>
            <SelectContent>
              <SelectItem value={ALL}>All assessments</SelectItem>
              {assessments?.items.map((a) => (
                <SelectItem key={a.id} value={String(a.id)}>{a.name}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        {showFilters && (
          <div className="mt-4 grid gap-4 border-t pt-4 animate-fade-in md:grid-cols-2 xl:grid-cols-3">
            <ChipFilter
              label="Severity" options={SEVERITIES} selected={severity}
              onChange={(v) => { setSeverity(v); setPage(1) }}
              renderOption={(v) => (v === "INFORMATIONAL" ? "Info" : titleCase(v))}
            />
            <ChipFilter
              label="Status" options={STATUSES} selected={status}
              onChange={(v) => { setStatus(v); setPage(1) }}
            />
            <ChipFilter
              label="Source scanner"
              options={(scanners ?? []).map((s) => s.name)}
              selected={source}
              onChange={(v) => { setSource(v); setPage(1) }}
              renderOption={(v) => scanners?.find((s) => s.name === v)?.label ?? v}
            />
            <div className="space-y-1.5">
              <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">SLA</p>
              <Select value={slaStatus} onValueChange={(v) => { setSlaStatus(v); setPage(1) }}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value={ALL}>Any SLA state</SelectItem>
                  <SelectItem value="OVERDUE">Overdue</SelectItem>
                  <SelectItem value="DUE_SOON">Due soon</SelectItem>
                  <SelectItem value="ON_TRACK">On track</SelectItem>
                </SelectContent>
              </Select>
            </div>
            {users && (
              <div className="space-y-1.5">
                <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">Assigned to</p>
                <Select value={assignedTo} onValueChange={(v) => { setAssignedTo(v); setPage(1) }}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value={ALL}>Anyone</SelectItem>
                    {users.map((u) => (
                      <SelectItem key={u.id} value={String(u.id)}>{u.full_name}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}
            <div className="flex items-end">
              <Button variant="ghost" size="sm" onClick={clearFilters} disabled={activeFilters === 0}>
                Clear all filters
              </Button>
            </div>
          </div>
        )}
      </Card>

      <Card className={cn("overflow-hidden transition-opacity", isFetching && "opacity-70")}>
        {isLoading ? (
          <TableSkeleton rows={8} cols={7} />
        ) : error ? (
          <ErrorState error={error} onRetry={refetch} />
        ) : data && data.items.length === 0 ? (
          <EmptyState
            icon={Bug}
            title="No findings match these filters"
            description={
              activeFilters > 0
                ? "Try widening or clearing the filters to see more results."
                : "Findings appear here once a scan completes or an analyst raises one manually."
            }
            action={activeFilters > 0 ? <Button variant="outline" onClick={clearFilters}>Clear filters</Button> : null}
          />
        ) : (
          <>
            <Table>
              <THead>
                <TR>
                  <TH className="w-24">ID</TH>
                  <SortableTH label="Severity" field="severity" sort={sort} onSort={toggleSort} className="w-32" />
                  <TH>Title</TH>
                  <SortableTH label="CVSS" field="cvss_score" sort={sort} onSort={toggleSort} className="w-20" />
                  <TH className="w-24">Risk</TH>
                  <SortableTH label="Status" field="status" sort={sort} onSort={toggleSort} className="w-40" />
                  <TH className="w-32">Source</TH>
                  <TH className="w-36">Assigned</TH>
                  <TH className="w-32">SLA</TH>
                  <SortableTH label="Updated" field="updated_at" sort={sort} onSort={toggleSort} className="w-28" />
                </TR>
              </THead>
              <TBody>
                {data?.items.map((finding, index) => (
                  <MotionTR key={finding.id} index={index} enter={enterRows} className="cursor-pointer">
                    <TD>
                      <Link to={`/findings/${finding.id}`} className="font-mono text-xs font-medium text-primary hover:underline">
                        {finding.reference}
                      </Link>
                    </TD>
                    <TD><SeverityBadge severity={finding.severity} /></TD>
                    <TD>
                      <Link to={`/findings/${finding.id}`} className="block max-w-xl">
                        <span className="line-clamp-1 font-medium hover:text-primary">{finding.title}</span>
                        <span className="mt-0.5 flex flex-wrap items-center gap-1.5">
                          {finding.endpoint && (
                            <span className="line-clamp-1 max-w-md font-mono text-[11px] text-muted-foreground">
                              {finding.endpoint}
                            </span>
                          )}
                          {finding.cwe_id && <Badge variant="muted" className="text-[10px]">{finding.cwe_id}</Badge>}
                          {finding.cve_ids?.slice(0, 1).map((cve) => (
                            <Badge key={cve} variant="muted" className="text-[10px]">{cve}</Badge>
                          ))}
                          {finding.data_origin === "SEEDED_DEMO" && <DemoBadge />}
                        </span>
                      </Link>
                    </TD>
                    <TD>
                      <span className="font-mono text-sm font-medium">
                        {finding.cvss_score?.toFixed(1) ?? "—"}
                      </span>
                    </TD>
                    <TD>
                      {finding.risk_level ? (
                        <SeverityBadge severity={finding.risk_level} showDot={false} />
                      ) : "—"}
                    </TD>
                    <TD><StatusBadge status={finding.status} /></TD>
                    <TD>
                      <Tooltip label={finding.source_count > 1 ? `Reported by ${finding.source_count} scanners` : undefined}>
                        <span className="inline-flex items-center gap-1">
                          <Badge variant="muted" className="text-[10px]">{finding.primary_source}</Badge>
                          {finding.source_count > 1 && (
                            <span className="text-[10px] font-medium text-primary">+{finding.source_count - 1}</span>
                          )}
                        </span>
                      </Tooltip>
                    </TD>
                    <TD>
                      {finding.assigned_to ? (
                        <span className="truncate text-xs">{finding.assigned_to.full_name}</span>
                      ) : (
                        <span className="text-xs text-muted-foreground">Unassigned</span>
                      )}
                    </TD>
                    <TD><SlaBadge sla={finding.sla} /></TD>
                    <TD className="whitespace-nowrap text-xs text-muted-foreground">
                      {relativeTime(finding.updated_at)}
                    </TD>
                  </MotionTR>
                ))}
              </TBody>
            </Table>
            {data && (
              <Pagination
                page={data.page} pages={data.pages} total={data.total}
                pageSize={data.page_size} onPage={setPage}
              />
            )}
          </>
        )}
      </Card>

      <NewFindingDialog open={newOpen} onOpenChange={setNewOpen} />
    </>
  )
}
