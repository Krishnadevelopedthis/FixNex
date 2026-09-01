import * as React from "react"
import { useMutation, useQueryClient } from "@tanstack/react-query"
import { CheckCircle2, Clock, Send, UserCheck, Wrench, XCircle } from "lucide-react"
import { findingApi } from "@/services/endpoints"
import { Button } from "@/components/ui/button"
import { Textarea } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Badge, SlaBadge, StatusBadge } from "@/components/ui/badge"
import { EmptyState, Separator } from "@/components/ui/misc"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { errorMessage, useToast } from "@/components/ui/toast"
import { formatDate, relativeTime, titleCase } from "@/lib/utils"
import { useAuth } from "@/hooks/useAuth"
import type { FindingDetail } from "@/types"

/** Statuses a developer is permitted to set; resolution requires a passing retest. */
const DEVELOPER_STATUSES = ["OPEN", "IN_PROGRESS", "READY_FOR_RETEST"]

export function RemediationPanel({ finding }: { finding: FindingDetail }) {
  const { can, user } = useAuth()
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const remediation = finding.remediation

  const [notes, setNotes] = React.useState(remediation?.developer_notes ?? "")
  const [status, setStatus] = React.useState(remediation?.status ?? "OPEN")
  const [fixSummary, setFixSummary] = React.useState(remediation?.fix_summary ?? "")

  React.useEffect(() => {
    setNotes(remediation?.developer_notes ?? "")
    setStatus(remediation?.status ?? "OPEN")
    setFixSummary(remediation?.fix_summary ?? "")
  }, [remediation])

  function invalidate() {
    queryClient.invalidateQueries({ queryKey: ["finding", finding.id] })
    queryClient.invalidateQueries({ queryKey: ["findings"] })
    queryClient.invalidateQueries({ queryKey: ["remediation"] })
    queryClient.invalidateQueries({ queryKey: ["dashboard"] })
  }

  const updateMutation = useMutation({
    mutationFn: () =>
      findingApi.updateRemediation(finding.id, {
        status,
        developer_notes: notes || undefined,
      }),
    onSuccess: () => { toast("success", "Remediation updated"); invalidate() },
    onError: (e) => toast("error", "Could not update remediation", errorMessage(e)),
  })

  const readyMutation = useMutation({
    mutationFn: () => findingApi.readyForRetest(finding.id, fixSummary || undefined),
    onSuccess: () => {
      toast("success", "Marked ready for retest", "A security engineer will now verify the fix.")
      invalidate()
    },
    onError: (e) => toast("error", "Could not request a retest", errorMessage(e)),
  })

  if (!remediation) {
    return (
      <EmptyState
        icon={Wrench}
        title="No remediation yet"
        description={
          finding.verification_status === "CONFIRMED"
            ? "Assign this confirmed finding to a developer to open remediation and start the SLA clock."
            : "A finding must be confirmed before it can be assigned for remediation."
        }
      />
    )
  }

  const isAssignee = remediation.assigned_to?.id === user?.id
  const canEdit = can("remediation:update") && (isAssignee || can("finding:assign"))
  const canRequestRetest =
    can("retest:request", "remediation:update") &&
    ["OPEN", "IN_PROGRESS", "REOPENED"].includes(remediation.status)
  const statusOptions = can("finding:assign")
    ? ["OPEN", "IN_PROGRESS", "READY_FOR_RETEST", "RETESTING", "RESOLVED", "REOPENED"]
    : DEVELOPER_STATUSES

  return (
    <div className="space-y-5">
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="space-y-0.5">
          <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">Status</p>
          <StatusBadge status={remediation.status} />
        </div>
        <div className="space-y-0.5">
          <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">Priority</p>
          <Badge variant="muted">{remediation.priority}</Badge>
        </div>
        <div className="space-y-0.5">
          <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">Assigned to</p>
          <p className="text-sm">{remediation.assigned_to?.full_name ?? "Unassigned"}</p>
        </div>
        <div className="space-y-0.5">
          <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">SLA</p>
          <SlaBadge sla={remediation.sla} />
        </div>
      </div>

      {remediation.sla_due_at && (
        <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <Clock className="h-3.5 w-3.5" />
          Due {formatDate(remediation.sla_due_at, true)}
          {remediation.reopened_count > 0 && (
            <span className="ml-2 text-severity-critical">
              · Reopened {remediation.reopened_count}×
            </span>
          )}
        </p>
      )}

      {remediation.recommendation && (
        <div className="space-y-1.5">
          <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
            Guidance from the security team
          </p>
          <p className="whitespace-pre-wrap rounded-md border bg-muted/30 p-3 text-sm">
            {remediation.recommendation}
          </p>
        </div>
      )}

      {canEdit && !["RESOLVED"].includes(remediation.status) && (
        <>
          <Separator />
          <div className="space-y-4">
            <p className="flex items-center gap-1.5 text-sm font-medium">
              <UserCheck className="h-4 w-4" /> Update progress
            </p>

            <div className="grid gap-3 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label>Status</Label>
                <Select value={status} onValueChange={setStatus}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {statusOptions.map((s) => (
                      <SelectItem key={s} value={s}>{titleCase(s)}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {!can("finding:assign") && (
                  <p className="text-[11px] text-muted-foreground">
                    A finding is only resolved by a passing retest, not by the developer.
                  </p>
                )}
              </div>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="dev-notes">Developer notes</Label>
              <Textarea
                id="dev-notes" rows={3} value={notes} onChange={(e) => setNotes(e.target.value)}
                placeholder="What have you changed so far?"
              />
            </div>

            <Button size="sm" loading={updateMutation.isPending} onClick={() => updateMutation.mutate()}>
              Save update
            </Button>
          </div>
        </>
      )}

      {canRequestRetest && (
        <>
          <Separator />
          <div className="space-y-3 rounded-lg border border-primary/25 bg-primary/5 p-4">
            <p className="text-sm font-medium">Fix complete?</p>
            <p className="text-xs text-muted-foreground">
              Marking this ready for retest hands it back to the security team for verification.
            </p>
            <Textarea
              rows={3} value={fixSummary} onChange={(e) => setFixSummary(e.target.value)}
              placeholder="Summarise the fix you applied…"
            />
            <Button size="sm" loading={readyMutation.isPending} onClick={() => readyMutation.mutate()}>
              <Send /> Mark ready for retest
            </Button>
          </div>
        </>
      )}

      {finding.retests.length > 0 && (
        <>
          <Separator />
          <div className="space-y-2">
            <p className="text-sm font-medium">Retest history</p>
            <ul className="space-y-2">
              {finding.retests.map((retest) => (
                <li key={retest.id} className="flex gap-3 rounded-md border p-3">
                  {retest.result === "PASS" ? (
                    <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-success" />
                  ) : (
                    <XCircle className="mt-0.5 h-4 w-4 shrink-0 text-severity-critical" />
                  )}
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-sm font-medium">
                        Retest {retest.result === "PASS" ? "passed" : "failed"}
                      </span>
                      <span className="text-[11px] text-muted-foreground">
                        {relativeTime(retest.performed_at ?? retest.created_at)}
                      </span>
                    </div>
                    {retest.summary && <p className="mt-0.5 text-sm text-muted-foreground">{retest.summary}</p>}
                    {retest.method && (
                      <p className="mt-0.5 font-mono text-[11px] text-muted-foreground">{retest.method}</p>
                    )}
                    {retest.performed_by && (
                      <p className="mt-0.5 text-[11px] text-muted-foreground">
                        by {retest.performed_by.full_name}
                      </p>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          </div>
        </>
      )}
    </div>
  )
}
