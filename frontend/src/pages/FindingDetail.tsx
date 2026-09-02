import * as React from "react"
import { Link, useParams } from "react-router-dom"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import {
  ArrowLeft, CheckCircle2, ChevronRight, Clock, ExternalLink, FileText, Gauge,
  MessageSquare, Radar, Send, Shield, ShieldCheck, SlidersHorizontal, Target as TargetIcon,
  UserPlus,
} from "lucide-react"
import { findingApi } from "@/services/endpoints"
import { PageHeader } from "@/layouts/AppLayout"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Textarea } from "@/components/ui/input"
import { Badge, DemoBadge, SeverityBadge, SlaBadge, StatusBadge } from "@/components/ui/badge"
import { EmptyState, ErrorState, Progress, Separator, Skeleton } from "@/components/ui/misc"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { errorMessage, useToast } from "@/components/ui/toast"
import { AssignDialog, RetestDialog, ScoreDialog, TriageDialog, VerifyDialog } from "@/components/finding-dialogs"
import { AITriagePanel } from "@/components/ai-triage-panel"
import { EvidencePanel } from "@/components/evidence-panel"
import { RemediationPanel } from "@/components/remediation-panel"
import { FindingTimeline } from "@/components/finding-timeline"
import { cn, formatDate, relativeTime, titleCase } from "@/lib/utils"
import { SEVERITY_VAR } from "@/lib/severity"
import { useAuth } from "@/hooks/useAuth"
import type { FindingDetail as FindingDetailType } from "@/types"

/** Small labelled value used throughout the detail page. */
function Field({ label, children, mono }: {
  label: string
  children: React.ReactNode
  mono?: boolean
}) {
  return (
    <div className="space-y-0.5">
      <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">{label}</p>
      <div className={cn("text-sm", mono && "break-all font-mono text-xs")}>{children ?? "—"}</div>
    </div>
  )
}

function ScoreRing({ score, label, tone }: { score?: number | null; label: string; tone: string }) {
  const value = score ?? 0
  const pct = Math.min(100, (value / 10) * 100)
  return (
    <div className="flex flex-col items-center gap-1.5">
      <div className="relative h-20 w-20">
        <svg viewBox="0 0 36 36" className="h-full w-full -rotate-90">
          <circle cx="18" cy="18" r="15.5" fill="none" stroke="hsl(var(--muted))" strokeWidth="3.5" />
          <circle
            cx="18" cy="18" r="15.5" fill="none" stroke={tone} strokeWidth="3.5"
            strokeLinecap="round" strokeDasharray={`${pct * 0.974} 100`}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-lg font-bold leading-none">{score?.toFixed(1) ?? "—"}</span>
          <span className="text-[9px] uppercase tracking-wider text-muted-foreground">/ 10</span>
        </div>
      </div>
      <p className="text-center text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
        {label}
      </p>
    </div>
  )
}

function CodeBlock({ title, content }: { title: string; content?: string | null }) {
  if (!content) return null
  return (
    <div className="space-y-1.5">
      <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">{title}</p>
      <pre className="max-h-80 overflow-auto rounded-md border bg-muted/50 p-3 font-mono text-[11px] leading-relaxed">
        {content}
      </pre>
    </div>
  )
}

export default function FindingDetailPage() {
  const { id } = useParams()
  const findingId = Number(id)
  const { can } = useAuth()
  const { toast } = useToast()
  const queryClient = useQueryClient()

  const [verifyOpen, setVerifyOpen] = React.useState(false)
  const [triageOpen, setTriageOpen] = React.useState(false)
  const [assignOpen, setAssignOpen] = React.useState(false)
  const [scoreOpen, setScoreOpen] = React.useState(false)
  const [retestOpen, setRetestOpen] = React.useState(false)
  const [comment, setComment] = React.useState("")

  const { data: finding, isLoading, error, refetch } = useQuery({
    queryKey: ["finding", findingId],
    queryFn: () => findingApi.get(findingId),
    enabled: Number.isFinite(findingId),
  })

  const commentMutation = useMutation({
    mutationFn: (body: string) => findingApi.comment(findingId, body),
    onSuccess: () => {
      setComment("")
      queryClient.invalidateQueries({ queryKey: ["finding", findingId] })
      toast("success", "Comment added")
    },
    onError: (err) => toast("error", "Could not add the comment", errorMessage(err)),
  })

  if (isLoading) {
    return (
      <>
        <Skeleton className="mb-4 h-8 w-64" />
        <div className="grid gap-4 lg:grid-cols-3">
          <Skeleton className="h-96 lg:col-span-2" />
          <Skeleton className="h-96" />
        </div>
      </>
    )
  }

  if (error || !finding) {
    return <Card><ErrorState error={error} onRetry={refetch} /></Card>
  }

  const f: FindingDetailType = finding
  const canVerify = can("finding:verify") && ["DISCOVERED", "NEEDS_VERIFICATION"].includes(f.status)
  const canTriage = can("finding:triage") && f.status === "CONFIRMED"
  const canAssign = can("finding:assign") && ["CONFIRMED", "TRIAGED"].includes(f.status)
  const canRetest = can("retest:create") && ["RETEST", "REMEDIATION"].includes(f.status)
  const canScore = can("finding:score")

  return (
    <>
      <div className="mb-4 flex items-center gap-1.5 text-sm text-muted-foreground">
        <Link to="/findings" className="inline-flex items-center gap-1 hover:text-foreground">
          <ArrowLeft className="h-3.5 w-3.5" /> Findings
        </Link>
        <ChevronRight className="h-3.5 w-3.5" />
        <span className="font-mono text-xs">{f.reference}</span>
      </div>

      <PageHeader
        title={f.title}
        badge={
          <span className="flex flex-wrap items-center gap-1.5">
            <SeverityBadge severity={f.severity} pulse />
            <StatusBadge status={f.status} />
            {f.data_origin === "SEEDED_DEMO" && <DemoBadge />}
            {f.data_origin === "MANUAL" && <Badge variant="outline">Manual finding</Badge>}
            {f.is_suppressed && <Badge variant="muted">Suppressed</Badge>}
          </span>
        }
        description={
          <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <span className="font-mono text-xs">{f.reference}</span>
            {f.target_name && (
              <span className="inline-flex items-center gap-1">
                <TargetIcon className="h-3.5 w-3.5" /> {f.target_name}
              </span>
            )}
            <span>First seen {relativeTime(f.first_seen_at ?? f.created_at)}</span>
          </span>
        }
        actions={
          <>
            {canVerify && (
              <Button onClick={() => setVerifyOpen(true)}>
                <ShieldCheck /> Verify
              </Button>
            )}
            {canTriage && (
              <Button onClick={() => setTriageOpen(true)}>
                <SlidersHorizontal /> Triage
              </Button>
            )}
            {canAssign && (
              <Button onClick={() => setAssignOpen(true)}>
                <UserPlus /> Assign
              </Button>
            )}
            {canRetest && (
              <Button onClick={() => setRetestOpen(true)}>
                <CheckCircle2 /> Retest
              </Button>
            )}
            {canScore && (
              <Button variant="outline" onClick={() => setScoreOpen(true)}>
                <Gauge /> Rescore
              </Button>
            )}
          </>
        }
      />

      {/* Verification banners */}
      {f.verification_status === "FALSE_POSITIVE" && (
        <Card className="mb-4 border-muted-foreground/30 bg-muted/40">
          <CardContent className="flex gap-3 p-4">
            <Shield className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" />
            <div className="space-y-1">
              <p className="text-sm font-medium">Verified as a false positive</p>
              <p className="text-sm text-muted-foreground">{f.false_positive_reason}</p>
              <p className="text-xs text-muted-foreground">
                Recorded by {f.verified_by?.full_name ?? "—"} on {formatDate(f.verified_at, true)}. Retained
                permanently for audit — false positives are never deleted.
              </p>
            </div>
          </CardContent>
        </Card>
      )}

      {f.status === "CLOSED" && (
        <Card className="mb-4 border-success/30 bg-success/5">
          <CardContent className="flex items-center gap-3 p-4">
            <CheckCircle2 className="h-4 w-4 shrink-0 text-success" />
            <p className="text-sm">
              <span className="font-medium">Closed</span> on {formatDate(f.closed_at, true)} after a passing retest.
            </p>
          </CardContent>
        </Card>
      )}

      <div className="grid gap-4 lg:grid-cols-3">
        {/* ---------------------------------------------------------- main */}
        <div className="space-y-4 lg:col-span-2">
          <Card>
            <Tabs defaultValue="overview">
              <div className="px-5 pt-4">
                <TabsList>
                  <TabsTrigger value="overview">Overview</TabsTrigger>
                  <TabsTrigger value="technical">Technical details</TabsTrigger>
                  <TabsTrigger value="evidence">
                    Evidence {f.evidence.length > 0 && <Badge variant="muted" className="ml-1">{f.evidence.length}</Badge>}
                  </TabsTrigger>
                  <TabsTrigger value="remediation">Remediation</TabsTrigger>
                  <TabsTrigger value="activity">
                    Activity <Badge variant="muted" className="ml-1">{f.history.length}</Badge>
                  </TabsTrigger>
                </TabsList>
              </div>

              <div className="p-5">
                <TabsContent value="overview" className="mt-0 space-y-5">
                  <div className="space-y-1.5">
                    <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                      Description
                    </p>
                    <p className="whitespace-pre-wrap text-sm leading-relaxed">
                      {f.description || "No description was provided."}
                    </p>
                  </div>

                  {can("finding:verify") && <AITriagePanel finding={f} />}

                  <Separator />

                  <div className="grid gap-4 sm:grid-cols-2">
                    <Field label="Affected target">
                      {f.target_id ? (
                        <Link to={`/targets?highlight=${f.target_id}`} className="text-primary hover:underline">
                          {f.target_name}
                        </Link>
                      ) : "—"}
                    </Field>
                    <Field label="Category">{f.category ?? "—"}</Field>
                    <Field label="Endpoint" mono>{f.endpoint ?? "—"}</Field>
                    <Field label="Parameter" mono>{f.parameter ?? "—"}</Field>
                    <Field label="HTTP method">{f.http_method ?? "—"}</Field>
                    <Field label="Confidence">
                      <span className="flex items-center gap-2">
                        <Progress value={f.confidence * 100} className="h-1.5 w-20" />
                        {(f.confidence * 100).toFixed(0)}%
                      </span>
                    </Field>
                  </div>

                  {f.remediation_recommendation && (
                    <>
                      <Separator />
                      <div className="space-y-1.5">
                        <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                          Recommended fix
                        </p>
                        <p className="whitespace-pre-wrap text-sm leading-relaxed">
                          {f.remediation_recommendation}
                        </p>
                      </div>
                    </>
                  )}

                  {f.references.length > 0 && (
                    <>
                      <Separator />
                      <div className="space-y-1.5">
                        <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                          References
                        </p>
                        <ul className="space-y-1">
                          {f.references.map((ref) => (
                            <li key={ref}>
                              <a
                                href={ref} target="_blank" rel="noreferrer noopener"
                                className="inline-flex items-center gap-1 text-sm text-primary hover:underline"
                              >
                                <ExternalLink className="h-3 w-3 shrink-0" />
                                <span className="break-all">{ref}</span>
                              </a>
                            </li>
                          ))}
                        </ul>
                      </div>
                    </>
                  )}
                </TabsContent>

                <TabsContent value="technical" className="mt-0 space-y-5">
                  <CodeBlock title="Evidence captured by the scanner" content={f.technical_details} />
                  <CodeBlock title="Request" content={f.request_snippet} />
                  <CodeBlock title="Response" content={f.response_snippet} />
                  {!f.technical_details && !f.request_snippet && !f.response_snippet && (
                    <EmptyState icon={FileText} title="No technical detail recorded" />
                  )}

                  <Separator />
                  <div className="space-y-2">
                    <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                      Detected by
                    </p>
                    {f.sources.length === 0 ? (
                      <p className="text-sm text-muted-foreground">No scanner sources recorded.</p>
                    ) : (
                      <ul className="divide-y rounded-md border">
                        {f.sources.map((source) => (
                          <li key={source.id} className="flex items-center gap-3 px-3 py-2">
                            <Radar className="h-4 w-4 shrink-0 text-muted-foreground" />
                            <div className="min-w-0 flex-1">
                              <p className="text-sm font-medium">{source.scanner_label ?? source.scanner}</p>
                              <p className="line-clamp-1 text-[11px] text-muted-foreground">
                                Reported as “{source.raw_title}”
                              </p>
                            </div>
                            <Badge variant="muted" className="shrink-0">
                              {(source.confidence * 100).toFixed(0)}% confidence
                            </Badge>
                          </li>
                        ))}
                      </ul>
                    )}
                    {f.source_count > 1 && (
                      <p className="text-xs text-muted-foreground">
                        This finding was reported by {f.source_count} scanners and correlated into a
                        single record{f.duplicate_hits > 0 ? ` (${f.duplicate_hits} duplicate reports merged)` : ""}.
                      </p>
                    )}
                  </div>
                </TabsContent>

                <TabsContent value="evidence" className="mt-0">
                  <EvidencePanel finding={f} />
                </TabsContent>

                <TabsContent value="remediation" className="mt-0">
                  <RemediationPanel finding={f} />
                </TabsContent>

                <TabsContent value="activity" className="mt-0 space-y-5">
                  <FindingTimeline history={f.history} />

                  <Separator />

                  <div className="space-y-3">
                    <p className="flex items-center gap-1.5 text-sm font-medium">
                      <MessageSquare className="h-4 w-4" /> Comments
                    </p>
                    {f.comments.length === 0 ? (
                      <p className="text-sm text-muted-foreground">No comments yet.</p>
                    ) : (
                      <ul className="space-y-3">
                        {f.comments.map((c) => (
                          <li key={c.id} className="rounded-md border bg-muted/30 p-3">
                            <div className="mb-1 flex items-center justify-between gap-2">
                              <span className="text-xs font-medium">{c.user?.full_name ?? "Unknown"}</span>
                              <span className="text-[11px] text-muted-foreground">
                                {relativeTime(c.created_at)}
                              </span>
                            </div>
                            <p className="whitespace-pre-wrap text-sm">{c.body}</p>
                          </li>
                        ))}
                      </ul>
                    )}
                    {can("finding:comment") && (
                      <div className="space-y-2">
                        <Textarea
                          value={comment}
                          onChange={(e) => setComment(e.target.value)}
                          placeholder="Add a comment for the team…"
                          rows={3}
                        />
                        <div className="flex justify-end">
                          <Button
                            size="sm"
                            disabled={!comment.trim()}
                            loading={commentMutation.isPending}
                            onClick={() => commentMutation.mutate(comment.trim())}
                          >
                            <Send /> Comment
                          </Button>
                        </div>
                      </div>
                    )}
                  </div>
                </TabsContent>
              </div>
            </Tabs>
          </Card>
        </div>

        {/* --------------------------------------------------------- aside */}
        <div className="space-y-4">
          {/* Scoring */}
          <Card>
            <CardHeader>
              <CardTitle>Scoring</CardTitle>
              <CardDescription>CVSS base score and FixNex contextual risk</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex justify-around">
                <ScoreRing
                  score={f.cvss_score}
                  label="CVSS base"
                  tone={SEVERITY_VAR[f.severity] ?? SEVERITY_VAR.INFORMATIONAL}
                />
                <ScoreRing
                  score={f.risk?.risk_score}
                  label="Contextual risk"
                  tone={SEVERITY_VAR[f.risk?.risk_level ?? "INFORMATIONAL"]}
                />
              </div>

              {f.cvss_vector && (
                <div className="space-y-1">
                  <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                    CVSS v{f.cvss_version ?? "3.1"} vector
                  </p>
                  <code className="block break-all rounded bg-muted px-2 py-1.5 font-mono text-[10px]">
                    {f.cvss_vector}
                  </code>
                  {(f.risk?.factors as any)?.estimated_cvss ? (
                    <p className="text-[11px] text-muted-foreground">
                      Estimated from the reported severity — the scanner supplied no vector.
                    </p>
                  ) : null}
                </div>
              )}

              {f.risk && (
                <div className="space-y-2 rounded-md border bg-muted/30 p-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-medium">Contextual risk</span>
                    <SeverityBadge severity={f.risk.risk_level} showDot={false} />
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <div><span className="text-muted-foreground">Impact:</span> {titleCase(f.risk.impact)}</div>
                    <div><span className="text-muted-foreground">Likelihood:</span> {titleCase(f.risk.likelihood)}</div>
                  </div>
                  <details className="group">
                    <summary className="cursor-pointer list-none text-xs text-primary hover:underline">
                      How was this calculated?
                    </summary>
                    <ul className="mt-2 space-y-1">
                      {f.risk.explanation.map((line, i) => (
                        <li key={i} className="flex gap-1.5 text-[11px] text-muted-foreground">
                          <span className="mt-1 h-1 w-1 shrink-0 rounded-full bg-muted-foreground/50" />
                          {line}
                        </li>
                      ))}
                    </ul>
                  </details>
                  <p className="border-t pt-2 text-[10px] leading-relaxed text-muted-foreground">
                    {f.risk.disclaimer}
                  </p>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Classification */}
          <Card>
            <CardHeader><CardTitle>Classification</CardTitle></CardHeader>
            <CardContent className="space-y-3">
              <Field label="CWE">
                {f.cwe_id ? (
                  <a
                    href={`https://cwe.mitre.org/data/definitions/${f.cwe_id.replace("CWE-", "")}.html`}
                    target="_blank" rel="noreferrer noopener"
                    className="inline-flex items-center gap-1 text-primary hover:underline"
                  >
                    {f.cwe_id}{f.cwe_name ? ` — ${f.cwe_name}` : ""}
                    <ExternalLink className="h-3 w-3 shrink-0" />
                  </a>
                ) : "Not classified"}
              </Field>

              <Field label="CVE">
                {f.cve_ids.length === 0 ? (
                  "None linked"
                ) : (
                  <ul className="space-y-2">
                    {f.cve_ids.map((cve) => {
                      const detail = f.cve_details.find((d) => d.cve_id === cve)
                      return (
                        <li key={cve} className="rounded-md border p-2">
                          <div className="flex items-center justify-between gap-2">
                            <a
                              href={detail?.url ?? `https://nvd.nist.gov/vuln/detail/${cve}`}
                              target="_blank" rel="noreferrer noopener"
                              className="inline-flex items-center gap-1 font-mono text-xs text-primary hover:underline"
                            >
                              {cve} <ExternalLink className="h-3 w-3" />
                            </a>
                            {detail?.cvss_score != null && (
                              <Badge variant="muted">CVSS {detail.cvss_score}</Badge>
                            )}
                          </div>
                          {detail?.description && (
                            <p className="mt-1 line-clamp-3 text-[11px] text-muted-foreground">
                              {detail.description}
                            </p>
                          )}
                          {detail && !detail.enriched && (
                            <p className="mt-1 text-[10px] text-muted-foreground">
                              Not enriched: {detail.detail}
                            </p>
                          )}
                        </li>
                      )
                    })}
                  </ul>
                )}
              </Field>
            </CardContent>
          </Card>

          {/* Workflow */}
          <Card>
            <CardHeader><CardTitle>Workflow</CardTitle></CardHeader>
            <CardContent className="space-y-3">
              <Field label="Status"><StatusBadge status={f.status} /></Field>
              <Field label="Verification">
                <span className="flex items-center gap-2">
                  <StatusBadge status={f.verification_status === "CONFIRMED" ? "CONFIRMED" : f.verification_status} />
                  {f.verified_by && (
                    <span className="text-xs text-muted-foreground">by {f.verified_by.full_name}</span>
                  )}
                </span>
              </Field>
              <Field label="Priority">{f.priority ?? "Not triaged"}</Field>
              <Field label="Assigned to">
                {f.assigned_to ? f.assigned_to.full_name : "Unassigned"}
              </Field>
              <Field label="SLA">
                <span className="flex flex-col gap-1">
                  <SlaBadge sla={f.sla} />
                  {f.sla?.due_at && (
                    <span className="inline-flex items-center gap-1 text-[11px] text-muted-foreground">
                      <Clock className="h-3 w-3" /> Due {formatDate(f.sla.due_at, true)}
                    </span>
                  )}
                </span>
              </Field>
              {f.verification_note && <Field label="Verification note">{f.verification_note}</Field>}
            </CardContent>
          </Card>

          {/* Provenance */}
          <Card>
            <CardHeader><CardTitle>Provenance</CardTitle></CardHeader>
            <CardContent className="space-y-3">
              <Field label="Origin">
                {f.data_origin === "REAL_SCAN" ? (
                  <span className="inline-flex items-center gap-1.5">
                    <Radar className="h-3.5 w-3.5 text-primary" /> Produced by an executed scan
                  </span>
                ) : f.data_origin === "MANUAL" ? (
                  "Raised manually by an analyst"
                ) : (
                  <span className="inline-flex items-center gap-1.5">
                    <DemoBadge /> Seeded demonstration data
                  </span>
                )}
              </Field>
              <Field label="Primary source">{f.primary_source}</Field>
              <Field label="Reported by">{f.source_count} scanner{f.source_count === 1 ? "" : "s"}</Field>
              <Field label="First seen">{formatDate(f.first_seen_at ?? f.created_at, true)}</Field>
              <Field label="Last seen">{formatDate(f.last_seen_at, true)}</Field>
            </CardContent>
          </Card>
        </div>
      </div>

      <VerifyDialog finding={f} open={verifyOpen} onOpenChange={setVerifyOpen} />
      <TriageDialog finding={f} open={triageOpen} onOpenChange={setTriageOpen} />
      <AssignDialog finding={f} open={assignOpen} onOpenChange={setAssignOpen} />
      <ScoreDialog finding={f} open={scoreOpen} onOpenChange={setScoreOpen} />
      <RetestDialog finding={f} open={retestOpen} onOpenChange={setRetestOpen} />
    </>
  )
}
