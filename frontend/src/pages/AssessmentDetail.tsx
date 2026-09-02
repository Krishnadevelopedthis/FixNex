import * as React from "react"
import { Link, useParams } from "react-router-dom"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import {
  AlertTriangle, ArrowLeft, Bug, CheckCircle2, ChevronRight, CircleSlash, Crosshair,
  FileText, Plus, Radar, ShieldCheck, Trash2, Waypoints,
} from "lucide-react"
import { assessmentApi, findingApi, reportApi, scanApi, auditApi } from "@/services/endpoints"
import { PageHeader } from "@/layouts/AppLayout"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Badge, DemoBadge, SeverityBadge, SlaBadge, StatusBadge } from "@/components/ui/badge"
import { EmptyState, ErrorState, Progress, Separator, Skeleton, Tooltip } from "@/components/ui/misc"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { ConfirmDialog } from "@/components/ui/confirm"
import { errorMessage, useToast } from "@/components/ui/toast"
import { NewScanDialog } from "@/components/scan-dialogs"
import { AddTargetDialog } from "@/components/target-dialogs"
import { GenerateReportDialog } from "@/components/report-dialogs"
import { AttackPathPanel } from "@/components/attack-path-graph"
import { CompliancePanel } from "@/components/compliance-panel"
import { SEVERITY_DOT } from "@/lib/severity"
import { cn, formatDate, relativeTime, titleCase } from "@/lib/utils"
import { useAuth } from "@/hooks/useAuth"

const SCOPE_TYPES = [
  { value: "DOMAIN", label: "Domain", hint: "example.edu — exact hostname only" },
  { value: "WILDCARD_DOMAIN", label: "Wildcard domain", hint: "*.example.edu — the domain and all subdomains" },
  { value: "URL", label: "URL prefix", hint: "https://example.edu/app — that path and below" },
  { value: "API_ENDPOINT", label: "API endpoint", hint: "https://api.example.edu/v1" },
  { value: "IP", label: "IP address", hint: "203.0.113.10" },
  { value: "CIDR", label: "CIDR range", hint: "203.0.113.0/24" },
]

function ScopeTab({ assessmentId }: { assessmentId: number }) {
  const { can } = useAuth()
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [ruleType, setRuleType] = React.useState("WILDCARD_DOMAIN")
  const [value, setValue] = React.useState("")
  const [note, setNote] = React.useState("")
  const [isExclusion, setIsExclusion] = React.useState(false)
  const [testValue, setTestValue] = React.useState("")
  const [deleting, setDeleting] = React.useState<number | null>(null)

  const { data: rules, isLoading } = useQuery({
    queryKey: ["scope", assessmentId],
    queryFn: () => assessmentApi.scope(assessmentId),
  })

  const addMutation = useMutation({
    mutationFn: () =>
      assessmentApi.addScope(assessmentId, {
        rule_type: ruleType, value, note: note || undefined, is_exclusion: isExclusion,
      }),
    onSuccess: () => {
      toast("success", "Scope rule added")
      setValue(""); setNote("")
      queryClient.invalidateQueries({ queryKey: ["scope", assessmentId] })
    },
    onError: (e) => toast("error", "Could not add the scope rule", errorMessage(e)),
  })

  const removeMutation = useMutation({
    mutationFn: (ruleId: number) => assessmentApi.removeScope(assessmentId, ruleId),
    onSuccess: () => {
      toast("success", "Scope rule removed")
      setDeleting(null)
      queryClient.invalidateQueries({ queryKey: ["scope", assessmentId] })
    },
    onError: (e) => toast("error", "Could not remove the rule", errorMessage(e)),
  })

  const checkMutation = useMutation({
    mutationFn: () => assessmentApi.checkScope(assessmentId, testValue),
  })

  const inclusions = rules?.filter((r) => !r.is_exclusion) ?? []
  const exclusions = rules?.filter((r) => r.is_exclusion) ?? []

  return (
    <div className="grid gap-4 lg:grid-cols-3">
      <div className="space-y-4 lg:col-span-2">
        <Card>
          <CardHeader>
            <CardTitle>Authorized scope</CardTitle>
            <CardDescription>
              A scan is only permitted against a target that matches an inclusion rule and no
              exclusion rule. Blocked attempts are written to the audit log.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {isLoading ? (
              <Skeleton className="h-24" />
            ) : rules?.length === 0 ? (
              <EmptyState
                icon={ShieldCheck}
                title="No scope defined"
                description="Add at least one rule before any target can be added or scanned."
              />
            ) : (
              <div className="space-y-4">
                <div className="space-y-2">
                  <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                    In scope ({inclusions.length})
                  </p>
                  <ul className="space-y-2">
                    {inclusions.map((rule) => (
                      <li key={rule.id} className="flex items-start gap-3 rounded-md border p-3">
                        <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-success" />
                        <div className="min-w-0 flex-1">
                          <p className="break-all font-mono text-sm">{rule.value}</p>
                          <p className="text-[11px] text-muted-foreground">
                            {titleCase(rule.rule_type)}
                            {rule.note ? ` · ${rule.note}` : ""}
                          </p>
                        </div>
                        {can("scope:manage") && (
                          <Button variant="ghost" size="icon-sm" onClick={() => setDeleting(rule.id)}>
                            <Trash2 className="h-4 w-4 text-destructive" />
                          </Button>
                        )}
                      </li>
                    ))}
                  </ul>
                </div>

                {exclusions.length > 0 && (
                  <div className="space-y-2">
                    <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                      Explicitly excluded ({exclusions.length}) — these always win
                    </p>
                    <ul className="space-y-2">
                      {exclusions.map((rule) => (
                        <li key={rule.id} className="flex items-start gap-3 rounded-md border border-destructive/30 bg-destructive/5 p-3">
                          <CircleSlash className="mt-0.5 h-4 w-4 shrink-0 text-destructive" />
                          <div className="min-w-0 flex-1">
                            <p className="break-all font-mono text-sm">{rule.value}</p>
                            <p className="text-[11px] text-muted-foreground">
                              {titleCase(rule.rule_type)}{rule.note ? ` · ${rule.note}` : ""}
                            </p>
                          </div>
                          {can("scope:manage") && (
                            <Button variant="ghost" size="icon-sm" onClick={() => setDeleting(rule.id)}>
                              <Trash2 className="h-4 w-4 text-destructive" />
                            </Button>
                          )}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>

        {can("scope:manage") && (
          <Card>
            <CardHeader><CardTitle>Add a scope rule</CardTitle></CardHeader>
            <CardContent className="space-y-3">
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="space-y-1.5">
                  <Label>Rule type</Label>
                  <Select value={ruleType} onValueChange={setRuleType}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {SCOPE_TYPES.map((t) => (
                        <SelectItem key={t.value} value={t.value}>{t.label}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <p className="text-[11px] text-muted-foreground">
                    {SCOPE_TYPES.find((t) => t.value === ruleType)?.hint}
                  </p>
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="scope-value">Value</Label>
                  <Input
                    id="scope-value" value={value} onChange={(e) => setValue(e.target.value)}
                    placeholder={SCOPE_TYPES.find((t) => t.value === ruleType)?.hint.split(" — ")[0]}
                    className="font-mono text-sm"
                  />
                </div>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="scope-note">Note</Label>
                <Input id="scope-note" value={note} onChange={(e) => setNote(e.target.value)} />
              </div>
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox" checked={isExclusion}
                  onChange={(e) => setIsExclusion(e.target.checked)}
                  className="h-4 w-4 rounded border-input"
                />
                Mark as an exclusion (explicitly out of scope)
              </label>
              <Button
                size="sm" disabled={!value.trim()} loading={addMutation.isPending}
                onClick={() => addMutation.mutate()}
              >
                <Plus /> Add rule
              </Button>
            </CardContent>
          </Card>
        )}
      </div>

      <Card className="h-fit">
        <CardHeader>
          <CardTitle>Scope checker</CardTitle>
          <CardDescription>Test whether a value would be permitted.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <Input
            value={testValue} onChange={(e) => setTestValue(e.target.value)}
            placeholder="https://portal.example.edu" className="font-mono text-sm"
          />
          <Button
            size="sm" variant="outline" className="w-full"
            disabled={!testValue.trim()} loading={checkMutation.isPending}
            onClick={() => checkMutation.mutate()}
          >
            Check scope
          </Button>
          {checkMutation.data && (
            <div
              className={cn(
                "rounded-md border p-3 text-sm",
                checkMutation.data.in_scope
                  ? "border-success/30 bg-success/10"
                  : "border-destructive/30 bg-destructive/10"
              )}
            >
              <p className="flex items-center gap-1.5 font-medium">
                {checkMutation.data.in_scope ? (
                  <><CheckCircle2 className="h-4 w-4 text-success" /> In scope</>
                ) : (
                  <><AlertTriangle className="h-4 w-4 text-destructive" /> Out of scope</>
                )}
              </p>
              <p className="mt-1 text-xs text-muted-foreground">{checkMutation.data.reason}</p>
            </div>
          )}
        </CardContent>
      </Card>

      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title="Remove this scope rule?"
        description="Targets that relied on this rule will no longer be scannable."
        confirmLabel="Remove"
        loading={removeMutation.isPending}
        onConfirm={() => deleting && removeMutation.mutate(deleting)}
      />
    </div>
  )
}

export default function AssessmentDetailPage() {
  const { id } = useParams()
  const assessmentId = Number(id)
  const { can } = useAuth()
  const [scanOpen, setScanOpen] = React.useState(false)
  const [targetOpen, setTargetOpen] = React.useState(false)
  const [reportOpen, setReportOpen] = React.useState(false)

  const { data: assessment, isLoading, error, refetch } = useQuery({
    queryKey: ["assessment", assessmentId],
    queryFn: () => assessmentApi.get(assessmentId),
    enabled: Number.isFinite(assessmentId),
  })
  const { data: targets } = useQuery({
    queryKey: ["assessment-targets", String(assessmentId)],
    queryFn: () => assessmentApi.targets(assessmentId),
    enabled: Number.isFinite(assessmentId),
  })
  const { data: scans } = useQuery({
    queryKey: ["scans", { assessment_id: assessmentId }],
    queryFn: () => scanApi.list({ assessment_id: assessmentId, page_size: 30 }),
    enabled: Number.isFinite(assessmentId),
  })
  const { data: findings } = useQuery({
    queryKey: ["findings", { assessment_id: assessmentId, page_size: 100 }],
    queryFn: () => findingApi.list({ assessment_id: assessmentId, page_size: 100 }),
    enabled: Number.isFinite(assessmentId),
  })
  const { data: reports } = useQuery({
    queryKey: ["reports", { assessment_id: assessmentId }],
    queryFn: () => reportApi.list({ assessment_id: assessmentId }),
    enabled: Number.isFinite(assessmentId),
  })
  const { data: attackPaths } = useQuery({
    queryKey: ["attack-paths", assessmentId],
    queryFn: () => assessmentApi.attackPaths(assessmentId),
    enabled: Number.isFinite(assessmentId),
  })
  const { data: compliance } = useQuery({
    queryKey: ["compliance", assessmentId],
    queryFn: () => assessmentApi.compliance(assessmentId),
    enabled: Number.isFinite(assessmentId),
  })
  const { data: activity } = useQuery({
    queryKey: ["audit", { assessment_id: assessmentId }],
    queryFn: () => auditApi.list({ assessment_id: assessmentId, page_size: 50 }),
    enabled: Number.isFinite(assessmentId) && can("audit:view"),
  })

  if (isLoading) {
    return <><Skeleton className="mb-4 h-9 w-72" /><Skeleton className="h-96" /></>
  }
  if (error || !assessment) {
    return <Card><ErrorState error={error} onRetry={refetch} /></Card>
  }

  const stats = assessment.stats

  return (
    <>
      <div className="mb-4 flex items-center gap-1.5 text-sm text-muted-foreground">
        <Link to="/assessments" className="inline-flex items-center gap-1 hover:text-foreground">
          <ArrowLeft className="h-3.5 w-3.5" /> Assessments
        </Link>
        <ChevronRight className="h-3.5 w-3.5" />
        <span className="font-mono text-xs">{assessment.reference}</span>
      </div>

      <PageHeader
        title={assessment.name}
        badge={
          <span className="flex items-center gap-1.5">
            <StatusBadge status={assessment.status} />
            {assessment.is_demo && <DemoBadge />}
          </span>
        }
        description={
          <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
            {assessment.client_name && <span>{assessment.client_name}</span>}
            {assessment.start_date && (
              <span>{formatDate(assessment.start_date)} → {formatDate(assessment.end_date)}</span>
            )}
          </span>
        }
        actions={
          <>
            {can("target:create") && (
              <Button variant="outline" onClick={() => setTargetOpen(true)}>
                <Crosshair /> Add target
              </Button>
            )}
            {can("scan:create") && (
              <Button onClick={() => setScanOpen(true)}><Radar /> New scan</Button>
            )}
            {can("report:create") && (
              <Button variant="outline" onClick={() => setReportOpen(true)}>
                <FileText /> Report
              </Button>
            )}
          </>
        }
      />

      {/* Summary counters */}
      {stats && (
        <div className="mb-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
          {[
            { label: "Targets", value: stats.targets },
            { label: "Scans", value: stats.scans },
            { label: "Findings", value: stats.findings_total },
            { label: "Open", value: stats.findings_open },
            { label: "Overdue", value: stats.overdue, tone: stats.overdue > 0 ? "text-severity-critical" : "" },
          ].map((item) => (
            <Card key={item.label}>
              <CardContent className="p-4">
                <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                  {item.label}
                </p>
                <p className={cn("text-2xl font-bold", item.tone)}>{item.value}</p>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="scope">Scope</TabsTrigger>
          <TabsTrigger value="targets">Targets <Badge variant="muted" className="ml-1">{targets?.length ?? 0}</Badge></TabsTrigger>
          <TabsTrigger value="scans">Scans <Badge variant="muted" className="ml-1">{scans?.total ?? 0}</Badge></TabsTrigger>
          <TabsTrigger value="findings">Findings <Badge variant="muted" className="ml-1">{findings?.total ?? 0}</Badge></TabsTrigger>
          <TabsTrigger value="attack-paths">
            <Waypoints className="h-3.5 w-3.5" /> Attack paths
            {(attackPaths?.summary.paths ?? 0) > 0 && (
              <Badge variant="muted" className="ml-1">{attackPaths?.summary.paths}</Badge>
            )}
          </TabsTrigger>
          <TabsTrigger value="reports">Reports <Badge variant="muted" className="ml-1">{reports?.total ?? 0}</Badge></TabsTrigger>
          {can("audit:view") && <TabsTrigger value="activity">Activity</TabsTrigger>}
        </TabsList>

        {/* -------------------------------------------------------- overview */}
        <TabsContent value="overview">
          <div className="grid gap-4 lg:grid-cols-3">
            <Card className="lg:col-span-2">
              <CardHeader><CardTitle>Engagement</CardTitle></CardHeader>
              <CardContent className="space-y-4">
                <p className="whitespace-pre-wrap text-sm leading-relaxed">
                  {assessment.description || "No description provided."}
                </p>
                {assessment.methodology && (
                  <>
                    <Separator />
                    <div className="space-y-1.5">
                      <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                        Methodology
                      </p>
                      <p className="whitespace-pre-wrap text-sm leading-relaxed text-muted-foreground">
                        {assessment.methodology}
                      </p>
                    </div>
                  </>
                )}
                {assessment.notes && (
                  <>
                    <Separator />
                    <div className="space-y-1.5">
                      <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">Notes</p>
                      <p className="whitespace-pre-wrap text-sm text-muted-foreground">{assessment.notes}</p>
                    </div>
                  </>
                )}
              </CardContent>
            </Card>

            <div className="space-y-4">
              {stats && (
                <Card>
                  <CardHeader><CardTitle>Findings by severity</CardTitle></CardHeader>
                  <CardContent className="space-y-2">
                    {(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"] as const).map((sev) => (
                      <div key={sev} className="flex items-center justify-between">
                        <span className="flex items-center gap-2 text-sm">
                          <span className={cn("sev-dot", SEVERITY_DOT[sev])} />
                          {sev === "INFORMATIONAL" ? "Info" : titleCase(sev)}
                        </span>
                        <span className="font-semibold">{stats.severity[sev]}</span>
                      </div>
                    ))}
                    <Separator />
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-muted-foreground">False positives</span>
                      <span className="font-semibold">{stats.findings_false_positive}</span>
                    </div>
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-muted-foreground">Closed</span>
                      <span className="font-semibold">{stats.findings_closed}</span>
                    </div>
                    <div className="pt-2">
                      <div className="mb-1 flex justify-between text-[11px] text-muted-foreground">
                        <span>Remediation progress</span>
                        <span>{stats.remediation_progress.toFixed(0)}%</span>
                      </div>
                      <Progress value={stats.remediation_progress} indicatorClassName="bg-success" />
                    </div>
                  </CardContent>
                </Card>
              )}

              {compliance && <CompliancePanel data={compliance} />}

              <Card>
                <CardHeader><CardTitle>Team</CardTitle></CardHeader>
                <CardContent className="space-y-2">
                  {assessment.members.length === 0 ? (
                    <p className="text-sm text-muted-foreground">No members assigned.</p>
                  ) : (
                    assessment.members.map((member) => (
                      <div key={member.id} className="flex items-center justify-between gap-2">
                        <div className="min-w-0">
                          <p className="truncate text-sm font-medium">{member.user.full_name}</p>
                          <p className="truncate text-[11px] text-muted-foreground">
                            {member.role_in_assessment ?? titleCase(member.user.role)}
                          </p>
                        </div>
                        <Badge variant="muted" className="shrink-0 text-[10px]">
                          {titleCase(member.user.role)}
                        </Badge>
                      </div>
                    ))
                  )}
                </CardContent>
              </Card>
            </div>
          </div>
        </TabsContent>

        <TabsContent value="scope"><ScopeTab assessmentId={assessmentId} /></TabsContent>

        {/* --------------------------------------------------------- targets */}
        <TabsContent value="targets">
          <Card className="overflow-hidden">
            {!targets || targets.length === 0 ? (
              <EmptyState
                icon={Crosshair}
                title="No targets yet"
                description="Add an authorized target that falls inside this assessment's scope."
                action={can("target:create") ? <Button onClick={() => setTargetOpen(true)}><Plus /> Add target</Button> : null}
              />
            ) : (
              <Table>
                <THead>
                  <TR>
                    <TH>Reference</TH><TH>Name</TH><TH>Type</TH><TH>Value</TH>
                    <TH>Status</TH><TH>Findings</TH><TH>Authorized</TH>
                  </TR>
                </THead>
                <TBody>
                  {targets.map((target) => (
                    <TR key={target.id}>
                      <TD className="font-mono text-xs">{target.reference}</TD>
                      <TD className="font-medium">{target.name}</TD>
                      <TD><Badge variant="muted">{titleCase(target.target_type)}</Badge></TD>
                      <TD className="max-w-xs truncate font-mono text-xs">{target.value}</TD>
                      <TD><StatusBadge status={target.status} /></TD>
                      <TD>{target.findings_count}</TD>
                      <TD className="text-xs text-muted-foreground">
                        {target.authorization_confirmed ? (
                          <Tooltip label={target.authorization_statement ?? ""}>
                            <span className="inline-flex items-center gap-1 text-success">
                              <ShieldCheck className="h-3.5 w-3.5" />
                              {target.authorized_by?.full_name ?? "Confirmed"}
                            </span>
                          </Tooltip>
                        ) : "Not confirmed"}
                      </TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
            )}
          </Card>
        </TabsContent>

        {/* ----------------------------------------------------------- scans */}
        <TabsContent value="scans">
          <Card className="overflow-hidden">
            {!scans || scans.items.length === 0 ? (
              <EmptyState
                icon={Radar}
                title="No scans yet"
                description="Run a scan against one of this assessment's authorized targets."
                action={can("scan:create") ? <Button onClick={() => setScanOpen(true)}><Radar /> New scan</Button> : null}
              />
            ) : (
              <Table>
                <THead>
                  <TR><TH>Reference</TH><TH>Target</TH><TH>Profile</TH><TH>Status</TH><TH>Progress</TH><TH>Findings</TH><TH>Started</TH></TR>
                </THead>
                <TBody>
                  {scans.items.map((scan) => (
                    <TR key={scan.id}>
                      <TD>
                        <Link to={`/scans/${scan.id}`} className="font-mono text-xs text-primary hover:underline">
                          {scan.reference}
                        </Link>
                      </TD>
                      <TD className="font-medium">{scan.target_name}</TD>
                      <TD><Badge variant="muted">{titleCase(scan.profile)}</Badge></TD>
                      <TD><StatusBadge status={scan.status} /></TD>
                      <TD className="w-32">
                        <Progress value={scan.progress} className="h-1.5" />
                      </TD>
                      <TD>{scan.findings_count}</TD>
                      <TD className="whitespace-nowrap text-xs text-muted-foreground">
                        {relativeTime(scan.created_at)}
                      </TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
            )}
          </Card>
        </TabsContent>

        {/* -------------------------------------------------------- findings */}
        <TabsContent value="findings">
          <Card className="overflow-hidden">
            {!findings || findings.items.length === 0 ? (
              <EmptyState icon={Bug} title="No findings yet" description="Findings appear once a scan completes." />
            ) : (
              <Table>
                <THead>
                  <TR><TH>ID</TH><TH>Severity</TH><TH>Title</TH><TH>CVSS</TH><TH>Status</TH><TH>Assigned</TH><TH>SLA</TH></TR>
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
                      <TD><StatusBadge status={finding.status} /></TD>
                      <TD className="text-xs">{finding.assigned_to?.full_name ?? "—"}</TD>
                      <TD><SlaBadge sla={finding.sla} /></TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
            )}
          </Card>
        </TabsContent>

        {/* ---------------------------------------------------- attack paths */}
        <TabsContent value="attack-paths">
          {attackPaths ? (
            <AttackPathPanel data={attackPaths} />
          ) : (
            <Skeleton className="h-96" />
          )}
        </TabsContent>

        {/* --------------------------------------------------------- reports */}
        <TabsContent value="reports">
          <Card className="overflow-hidden">
            {!reports?.items?.length ? (
              <EmptyState
                icon={FileText}
                title="No reports generated"
                description="Generate a PDF, CSV or JSON report of this assessment."
                action={can("report:create") ? <Button onClick={() => setReportOpen(true)}><FileText /> Generate report</Button> : null}
              />
            ) : (
              <Table>
                <THead>
                  <TR><TH>Reference</TH><TH>Title</TH><TH>Format</TH><TH>Status</TH><TH>Generated</TH></TR>
                </THead>
                <TBody>
                  {reports.items.map((report) => (
                    <TR key={report.id}>
                      <TD className="font-mono text-xs">{report.reference}</TD>
                      <TD className="font-medium">{report.title}</TD>
                      <TD><Badge variant="muted">{report.format}</Badge></TD>
                      <TD><StatusBadge status={report.status === "READY" ? "COMPLETED" : report.status} /></TD>
                      <TD className="text-xs text-muted-foreground">{relativeTime(report.created_at)}</TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
            )}
          </Card>
        </TabsContent>

        {/* -------------------------------------------------------- activity */}
        {can("audit:view") && (
          <TabsContent value="activity">
            <Card>
              <CardContent className="p-0">
                {!activity || activity.items.length === 0 ? (
                  <EmptyState icon={FileText} title="No recorded activity" />
                ) : (
                  <ul className="divide-y">
                    {activity.items.map((entry) => (
                      <li key={entry.id} className="flex items-start gap-3 px-5 py-3">
                        <div className="min-w-0 flex-1">
                          <p className="text-sm">{entry.description ?? titleCase(entry.action)}</p>
                          <p className="text-[11px] text-muted-foreground">
                            {entry.actor_email ?? "system"} · {formatDate(entry.created_at, true)}
                          </p>
                        </div>
                        <Badge variant="muted" className="shrink-0 font-mono text-[10px]">{entry.action}</Badge>
                      </li>
                    ))}
                  </ul>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        )}
      </Tabs>

      <NewScanDialog open={scanOpen} onOpenChange={setScanOpen} assessmentId={assessmentId} />
      <AddTargetDialog open={targetOpen} onOpenChange={setTargetOpen} assessmentId={assessmentId} />
      <GenerateReportDialog open={reportOpen} onOpenChange={setReportOpen} assessmentId={assessmentId} />
    </>
  )
}
