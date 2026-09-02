import * as React from "react"
import { useNavigate } from "react-router-dom"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { AlertTriangle, CheckCircle2, Info, XCircle } from "lucide-react"
import { assessmentApi, findingApi, userApi } from "@/services/endpoints"
import { Button } from "@/components/ui/button"
import { Input, Textarea } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { errorMessage, useToast } from "@/components/ui/toast"
import { SEVERITIES } from "@/lib/severity"
import { titleCase } from "@/lib/utils"
import type { FindingDetail } from "@/types"

const PRIORITIES = ["P1", "P2", "P3", "P4"]

/** Invalidates every query a finding mutation can affect. */
function useFindingInvalidation(findingId?: number) {
  const queryClient = useQueryClient()
  return React.useCallback(() => {
    if (findingId) queryClient.invalidateQueries({ queryKey: ["finding", findingId] })
    queryClient.invalidateQueries({ queryKey: ["findings"] })
    queryClient.invalidateQueries({ queryKey: ["remediation"] })
    queryClient.invalidateQueries({ queryKey: ["dashboard"] })
    queryClient.invalidateQueries({ queryKey: ["assessment"] })
  }, [queryClient, findingId])
}

/* ------------------------------------------------------------------ verify */
export function VerifyDialog({ finding, open, onOpenChange }: {
  finding: FindingDetail
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const [confirmed, setConfirmed] = React.useState(true)
  const [reason, setReason] = React.useState("")
  const [note, setNote] = React.useState("")
  const { toast } = useToast()
  const invalidate = useFindingInvalidation(finding.id)

  React.useEffect(() => {
    if (open) { setConfirmed(true); setReason(""); setNote("") }
  }, [open])

  const mutation = useMutation({
    mutationFn: () =>
      findingApi.verify(finding.id, {
        confirmed,
        reason: confirmed ? undefined : reason,
        note: note || undefined,
      }),
    onSuccess: () => {
      toast("success", confirmed ? "Finding confirmed" : "Recorded as a false positive",
        confirmed ? "It can now be triaged and assigned." : "Retained in full for audit and history.")
      invalidate()
      onOpenChange(false)
    },
    onError: (error) => toast("error", "Could not save the verification", errorMessage(error)),
  })

  const reasonRequired = !confirmed && reason.trim().length === 0

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Verify finding</DialogTitle>
          <DialogDescription>
            Record the outcome of your manual verification of {finding.reference}.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <button
              type="button"
              onClick={() => setConfirmed(true)}
              className={`flex flex-col items-start gap-1 rounded-lg border p-3 text-left transition-colors ${
                confirmed ? "border-severity-high bg-severity-high/10" : "hover:bg-accent"
              }`}
            >
              <span className="flex items-center gap-2 text-sm font-medium">
                <CheckCircle2 className="h-4 w-4 text-severity-high" /> Confirmed
              </span>
              <span className="text-xs text-muted-foreground">
                The issue is real and reproducible.
              </span>
            </button>
            <button
              type="button"
              onClick={() => setConfirmed(false)}
              className={`flex flex-col items-start gap-1 rounded-lg border p-3 text-left transition-colors ${
                !confirmed ? "border-muted-foreground bg-muted" : "hover:bg-accent"
              }`}
            >
              <span className="flex items-center gap-2 text-sm font-medium">
                <XCircle className="h-4 w-4 text-muted-foreground" /> False positive
              </span>
              <span className="text-xs text-muted-foreground">
                The scanner was wrong; kept for audit.
              </span>
            </button>
          </div>

          {!confirmed && (
            <div className="space-y-1.5">
              <Label htmlFor="fp-reason">
                Justification <span className="text-destructive">*</span>
              </Label>
              <Textarea
                id="fp-reason"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder="Explain why this is not exploitable — for example, the input is HTML-encoded before rendering."
                rows={4}
              />
              <p className="text-xs text-muted-foreground">
                Required. This justification is retained permanently for audit.
              </p>
            </div>
          )}

          <div className="space-y-1.5">
            <Label htmlFor="verify-note">Verification note</Label>
            <Textarea
              id="verify-note"
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="How did you verify this? Tooling, payloads, observed behaviour…"
              rows={3}
            />
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button
            loading={mutation.isPending}
            disabled={reasonRequired}
            onClick={() => mutation.mutate()}
          >
            {confirmed ? "Confirm finding" : "Mark false positive"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/* ------------------------------------------------------------------ triage */
export function TriageDialog({ finding, open, onOpenChange }: {
  finding: FindingDetail
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const suggested = { CRITICAL: "P1", HIGH: "P2", MEDIUM: "P3", LOW: "P4", INFORMATIONAL: "P4" }[finding.severity] ?? "P3"
  const [priority, setPriority] = React.useState(suggested)
  const [note, setNote] = React.useState("")
  const { toast } = useToast()
  const invalidate = useFindingInvalidation(finding.id)

  React.useEffect(() => { if (open) { setPriority(suggested); setNote("") } }, [open, suggested])

  const mutation = useMutation({
    mutationFn: () => findingApi.triage(finding.id, { priority, note: note || undefined }),
    onSuccess: () => {
      toast("success", `Triaged as ${priority}`)
      invalidate()
      onOpenChange(false)
    },
    onError: (error) => toast("error", "Could not triage the finding", errorMessage(error)),
  })

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="sm">
        <DialogHeader>
          <DialogTitle>Triage finding</DialogTitle>
          <DialogDescription>Set the remediation priority for {finding.reference}.</DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div className="space-y-1.5">
            <Label>Priority</Label>
            <div className="grid grid-cols-4 gap-2">
              {PRIORITIES.map((p) => (
                <button
                  key={p}
                  onClick={() => setPriority(p)}
                  className={`rounded-md border py-2 text-sm font-medium transition-colors ${
                    priority === p ? "border-primary bg-primary/10 text-primary" : "hover:bg-accent"
                  }`}
                >
                  {p}
                </button>
              ))}
            </div>
            <p className="text-xs text-muted-foreground">
              Suggested {suggested} based on {titleCase(finding.severity)} severity.
            </p>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="triage-note">Note</Label>
            <Textarea id="triage-note" value={note} onChange={(e) => setNote(e.target.value)} rows={3} />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button loading={mutation.isPending} onClick={() => mutation.mutate()}>Triage</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/* ------------------------------------------------------------------ assign */
export function AssignDialog({ finding, open, onOpenChange }: {
  finding: FindingDetail
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const [assignee, setAssignee] = React.useState("")
  const [priority, setPriority] = React.useState(finding.priority ?? "P3")
  const [slaHours, setSlaHours] = React.useState("")
  const [recommendation, setRecommendation] = React.useState("")
  const { toast } = useToast()
  const invalidate = useFindingInvalidation(finding.id)

  const { data: users } = useQuery({ queryKey: ["users", "picker"], queryFn: () => userApi.list(true), enabled: open })

  React.useEffect(() => {
    if (open) {
      setAssignee("")
      setPriority(finding.priority ?? "P3")
      setSlaHours("")
      setRecommendation(finding.remediation_recommendation ?? "")
    }
  }, [open, finding])

  const mutation = useMutation({
    mutationFn: () =>
      findingApi.assign(finding.id, {
        assigned_to_id: Number(assignee),
        priority,
        sla_hours: slaHours ? Number(slaHours) : undefined,
        recommendation: recommendation || undefined,
      }),
    onSuccess: () => {
      toast("success", "Finding assigned", "Remediation is now open with an SLA deadline.")
      invalidate()
      onOpenChange(false)
    },
    onError: (error) => toast("error", "Could not assign the finding", errorMessage(error)),
  })

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Assign for remediation</DialogTitle>
          <DialogDescription>
            Hand {finding.reference} to a developer and start the SLA clock.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div className="space-y-1.5">
            <Label>Assign to <span className="text-destructive">*</span></Label>
            <Select value={assignee} onValueChange={setAssignee}>
              <SelectTrigger><SelectValue placeholder="Choose a team member" /></SelectTrigger>
              <SelectContent>
                {users?.map((u) => (
                  <SelectItem key={u.id} value={String(u.id)}>
                    {u.full_name} — {titleCase(u.role)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label>Priority</Label>
              <Select value={priority} onValueChange={setPriority}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  {PRIORITIES.map((p) => <SelectItem key={p} value={p}>{p}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="sla-hours">SLA override (hours)</Label>
              <Input
                id="sla-hours" type="number" min={1} value={slaHours}
                onChange={(e) => setSlaHours(e.target.value)}
                placeholder="Default for severity"
              />
            </div>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="assign-rec">Remediation guidance</Label>
            <Textarea
              id="assign-rec" rows={4} value={recommendation}
              onChange={(e) => setRecommendation(e.target.value)}
              placeholder="What should the developer change?"
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button loading={mutation.isPending} disabled={!assignee} onClick={() => mutation.mutate()}>
            Assign
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/* ------------------------------------------------------------------- score */
export function ScoreDialog({ finding, open, onOpenChange }: {
  finding: FindingDetail
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const [vector, setVector] = React.useState(finding.cvss_vector ?? "")
  const [severity, setSeverity] = React.useState(finding.severity)
  const [cwe, setCwe] = React.useState(finding.cwe_id ?? "")
  const [criticality, setCriticality] = React.useState("")
  const [sensitivity, setSensitivity] = React.useState("")
  const [exposure, setExposure] = React.useState("")
  const [note, setNote] = React.useState("")
  const { toast } = useToast()
  const invalidate = useFindingInvalidation(finding.id)

  React.useEffect(() => {
    if (open) {
      setVector(finding.cvss_vector ?? "")
      setSeverity(finding.severity)
      setCwe(finding.cwe_id ?? "")
      setCriticality(""); setSensitivity(""); setExposure(""); setNote("")
    }
  }, [open, finding])

  const mutation = useMutation({
    mutationFn: () =>
      findingApi.score(finding.id, {
        cvss_vector: vector || undefined,
        severity,
        cwe_id: cwe || undefined,
        asset_criticality: criticality || undefined,
        data_sensitivity: sensitivity || undefined,
        exposure: exposure || undefined,
        note: note || undefined,
      }),
    onSuccess: () => {
      toast("success", "Scoring updated", "CVSS and contextual risk were recalculated.")
      invalidate()
      onOpenChange(false)
    },
    onError: (error) => toast("error", "Could not update the score", errorMessage(error)),
  })

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>Adjust scoring and risk context</DialogTitle>
          <DialogDescription>
            CVSS describes the vulnerability; the context below drives the separate
            FixNex contextual risk score.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="cvss-vector">CVSS v3.1 vector</Label>
            <Input
              id="cvss-vector" value={vector} onChange={(e) => setVector(e.target.value)}
              placeholder="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
              className="font-mono text-xs"
            />
            <p className="text-xs text-muted-foreground">
              Scored with the reference CVSS implementation; an invalid vector is rejected.
            </p>
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label>Severity</Label>
              <Select value={severity} onValueChange={(v) => setSeverity(v as any)}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  {SEVERITIES.map((s) => <SelectItem key={s} value={s}>{titleCase(s)}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="cwe">CWE</Label>
              <Input id="cwe" value={cwe} onChange={(e) => setCwe(e.target.value)} placeholder="CWE-89" />
            </div>
          </div>

          <div className="rounded-lg border bg-muted/40 p-3">
            <p className="mb-3 flex items-center gap-1.5 text-xs font-medium">
              <Info className="h-3.5 w-3.5" /> Contextual risk inputs (leave blank to inherit from the asset)
            </p>
            <div className="grid gap-3 sm:grid-cols-3">
              <div className="space-y-1.5">
                <Label className="text-xs">Asset criticality</Label>
                <Select value={criticality} onValueChange={setCriticality}>
                  <SelectTrigger><SelectValue placeholder="Inherit" /></SelectTrigger>
                  <SelectContent>
                    {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((v) => (
                      <SelectItem key={v} value={v}>{titleCase(v)}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">Data sensitivity</Label>
                <Select value={sensitivity} onValueChange={setSensitivity}>
                  <SelectTrigger><SelectValue placeholder="Inherit" /></SelectTrigger>
                  <SelectContent>
                    {["HIGH", "MEDIUM", "LOW", "NONE"].map((v) => (
                      <SelectItem key={v} value={v}>{titleCase(v)}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">Exposure</Label>
                <Select value={exposure} onValueChange={setExposure}>
                  <SelectTrigger><SelectValue placeholder="Inherit" /></SelectTrigger>
                  <SelectContent>
                    {["INTERNET_FACING", "INTERNAL", "ISOLATED"].map((v) => (
                      <SelectItem key={v} value={v}>{titleCase(v)}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="score-note">Reason for the change</Label>
            <Textarea id="score-note" rows={2} value={note} onChange={(e) => setNote(e.target.value)} />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button loading={mutation.isPending} onClick={() => mutation.mutate()}>Save scoring</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/* ------------------------------------------------------------------ retest */
export function RetestDialog({ finding, open, onOpenChange }: {
  finding: FindingDetail
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const [result, setResult] = React.useState<"PASS" | "FAIL">("PASS")
  const [summary, setSummary] = React.useState("")
  const [method, setMethod] = React.useState("")
  const { toast } = useToast()
  const invalidate = useFindingInvalidation(finding.id)

  React.useEffect(() => { if (open) { setResult("PASS"); setSummary(""); setMethod("") } }, [open])

  const mutation = useMutation({
    mutationFn: () => findingApi.retest(finding.id, { result, summary: summary || undefined, method: method || undefined }),
    onSuccess: () => {
      toast(
        "success",
        result === "PASS" ? "Retest passed — finding closed" : "Retest failed — sent back to remediation",
        result === "PASS" ? "The fix was verified." : "The remediation was reopened for the developer."
      )
      invalidate()
      onOpenChange(false)
    },
    onError: (error) => toast("error", "Could not record the retest", errorMessage(error)),
  })

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Record retest result</DialogTitle>
          <DialogDescription>
            Verify whether the fix for {finding.reference} actually resolves the issue.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <button
              type="button"
              onClick={() => setResult("PASS")}
              className={`flex flex-col items-start gap-1 rounded-lg border p-3 text-left transition-colors ${
                result === "PASS" ? "border-success bg-success/10" : "hover:bg-accent"
              }`}
            >
              <span className="flex items-center gap-2 text-sm font-medium">
                <CheckCircle2 className="h-4 w-4 text-success" /> Pass
              </span>
              <span className="text-xs text-muted-foreground">Fixed — the finding will be closed.</span>
            </button>
            <button
              type="button"
              onClick={() => setResult("FAIL")}
              className={`flex flex-col items-start gap-1 rounded-lg border p-3 text-left transition-colors ${
                result === "FAIL" ? "border-severity-critical bg-severity-critical/10" : "hover:bg-accent"
              }`}
            >
              <span className="flex items-center gap-2 text-sm font-medium">
                <AlertTriangle className="h-4 w-4 text-severity-critical" /> Fail
              </span>
              <span className="text-xs text-muted-foreground">Still exploitable — reopens remediation.</span>
            </button>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="retest-summary">What did you observe?</Label>
            <Textarea
              id="retest-summary" rows={3} value={summary}
              onChange={(e) => setSummary(e.target.value)}
              placeholder="Result of re-running the original proof of concept…"
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="retest-method">Method</Label>
            <Input
              id="retest-method" value={method} onChange={(e) => setMethod(e.target.value)}
              placeholder="e.g. Re-ran the original payload with curl"
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button
            variant={result === "PASS" ? "success" : "destructive"}
            loading={mutation.isPending}
            onClick={() => mutation.mutate()}
          >
            Record {result.toLowerCase()}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/* ------------------------------------------------------- new manual finding */
export function NewFindingDialog({ open, onOpenChange, assessmentId }: {
  open: boolean
  onOpenChange: (open: boolean) => void
  assessmentId?: number
}) {
  const [assessment, setAssessment] = React.useState(assessmentId ? String(assessmentId) : "")
  const [target, setTarget] = React.useState("")
  const [title, setTitle] = React.useState("")
  const [description, setDescription] = React.useState("")
  const [severity, setSeverity] = React.useState("MEDIUM")
  const [endpoint, setEndpoint] = React.useState("")
  const [cwe, setCwe] = React.useState("")
  const [vector, setVector] = React.useState("")
  const [recommendation, setRecommendation] = React.useState("")
  const { toast } = useToast()
  const navigate = useNavigate()
  const invalidate = useFindingInvalidation()

  const { data: assessments } = useQuery({
    queryKey: ["assessments", "picker"],
    queryFn: () => assessmentApi.list({ page_size: 100 }),
    enabled: open,
  })
  const { data: targets } = useQuery({
    queryKey: ["assessment-targets", assessment],
    queryFn: () => assessmentApi.targets(Number(assessment)),
    enabled: open && !!assessment,
  })

  React.useEffect(() => {
    if (open) {
      setAssessment(assessmentId ? String(assessmentId) : "")
      setTarget(""); setTitle(""); setDescription(""); setSeverity("MEDIUM")
      setEndpoint(""); setCwe(""); setVector(""); setRecommendation("")
    }
  }, [open, assessmentId])

  const mutation = useMutation({
    mutationFn: () =>
      findingApi.create({
        assessment_id: Number(assessment),
        target_id: target ? Number(target) : undefined,
        title,
        description: description || undefined,
        severity,
        endpoint: endpoint || undefined,
        cwe_id: cwe || undefined,
        cvss_vector: vector || undefined,
        remediation_recommendation: recommendation || undefined,
      }),
    onSuccess: (created) => {
      toast("success", "Finding raised", `${created.reference} was created from manual testing.`)
      invalidate()
      onOpenChange(false)
      navigate(`/findings/${created.id}`)
    },
    onError: (error) => toast("error", "Could not create the finding", errorMessage(error)),
  })

  const valid = assessment && title.trim().length >= 4

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>Raise a manual finding</DialogTitle>
          <DialogDescription>
            For issues discovered during hands-on testing. It is recorded with a
            manual origin, never presented as a scanner result.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label>Assessment <span className="text-destructive">*</span></Label>
              <Select value={assessment} onValueChange={(v) => { setAssessment(v); setTarget("") }}>
                <SelectTrigger><SelectValue placeholder="Choose an assessment" /></SelectTrigger>
                <SelectContent>
                  {assessments?.items.map((a) => (
                    <SelectItem key={a.id} value={String(a.id)}>{a.name}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label>Target</Label>
              <Select value={target} onValueChange={setTarget} disabled={!assessment}>
                <SelectTrigger><SelectValue placeholder="Optional" /></SelectTrigger>
                <SelectContent>
                  {targets?.map((t) => (
                    <SelectItem key={t.id} value={String(t.id)}>{t.name}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="nf-title">Title <span className="text-destructive">*</span></Label>
            <Input
              id="nf-title" value={title} onChange={(e) => setTitle(e.target.value)}
              placeholder="e.g. Insecure direct object reference on /api/students/{id}"
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="nf-desc">Description</Label>
            <Textarea
              id="nf-desc" rows={4} value={description} onChange={(e) => setDescription(e.target.value)}
              placeholder="What is the issue, how did you find it, and what is the impact?"
            />
          </div>

          <div className="grid gap-3 sm:grid-cols-3">
            <div className="space-y-1.5">
              <Label>Severity</Label>
              <Select value={severity} onValueChange={setSeverity}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SEVERITIES.map((s) => <SelectItem key={s} value={s}>{titleCase(s)}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="nf-cwe">CWE</Label>
              <Input id="nf-cwe" value={cwe} onChange={(e) => setCwe(e.target.value)} placeholder="CWE-639" />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="nf-endpoint">Endpoint</Label>
              <Input
                id="nf-endpoint" value={endpoint} onChange={(e) => setEndpoint(e.target.value)}
                placeholder="https://…"
              />
            </div>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="nf-vector">CVSS vector</Label>
            <Input
              id="nf-vector" value={vector} onChange={(e) => setVector(e.target.value)}
              className="font-mono text-xs"
              placeholder="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="nf-rec">Remediation recommendation</Label>
            <Textarea id="nf-rec" rows={3} value={recommendation} onChange={(e) => setRecommendation(e.target.value)} />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button loading={mutation.isPending} disabled={!valid} onClick={() => mutation.mutate()}>
            Create finding
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
