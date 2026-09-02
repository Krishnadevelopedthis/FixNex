import * as React from "react"
import { useNavigate } from "react-router-dom"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { AlertTriangle, CheckCircle2, Radar, ShieldAlert, Upload, XCircle } from "lucide-react"
import { assessmentApi, scanApi } from "@/services/endpoints"
import { Button } from "@/components/ui/button"
import { Label } from "@/components/ui/label"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { Checkbox } from "@/components/ui/misc"
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { errorMessage, useToast } from "@/components/ui/toast"
import { AUTHORIZATION_STATEMENT } from "@/components/target-dialogs"
import { cn } from "@/lib/utils"

export function NewScanDialog({ open, onOpenChange, assessmentId, targetId }: {
  open: boolean
  onOpenChange: (open: boolean) => void
  assessmentId?: number
  targetId?: number
}) {
  const [assessment, setAssessment] = React.useState(assessmentId ? String(assessmentId) : "")
  const [target, setTarget] = React.useState(targetId ? String(targetId) : "")
  const [profile, setProfile] = React.useState("STANDARD")
  const [authorized, setAuthorized] = React.useState(false)
  const { toast } = useToast()
  const navigate = useNavigate()
  const queryClient = useQueryClient()

  React.useEffect(() => {
    if (open) {
      setAssessment(assessmentId ? String(assessmentId) : "")
      setTarget(targetId ? String(targetId) : "")
      setProfile("STANDARD")
      setAuthorized(false)
    }
  }, [open, assessmentId, targetId])

  const { data: assessments } = useQuery({
    queryKey: ["assessments", "picker"],
    queryFn: () => assessmentApi.list({ page_size: 100 }),
    enabled: open && !assessmentId,
  })
  const { data: targets } = useQuery({
    queryKey: ["assessment-targets", assessment],
    queryFn: () => assessmentApi.targets(Number(assessment)),
    enabled: open && !!assessment,
  })
  const { data: profiles } = useQuery({ queryKey: ["profiles"], queryFn: scanApi.profiles, enabled: open })
  const { data: scanners } = useQuery({ queryKey: ["scanners"], queryFn: scanApi.scanners, enabled: open })

  const mutation = useMutation({
    mutationFn: () =>
      scanApi.create({
        assessment_id: Number(assessment),
        target_id: Number(target),
        profile,
        authorization_confirmed: authorized,
      }),
    onSuccess: (scan) => {
      toast("success", "Scan queued", `${scan.reference} is starting.`)
      queryClient.invalidateQueries({ queryKey: ["scans"] })
      queryClient.invalidateQueries({ queryKey: ["dashboard"] })
      onOpenChange(false)
      navigate(`/scans/${scan.id}`)
    },
    onError: (e) => toast("error", "Could not start the scan", errorMessage(e)),
  })

  const selectedProfile = profiles?.find((p) => p.name === profile)
  const selectedTarget = targets?.find((t) => String(t.id) === target)
  const valid = assessment && target && authorized

  // Which of the profile's scanners can actually run right now.
  const profileScanners = (selectedProfile?.scanners ?? []).map((name) => {
    const info = scanners?.find((s) => s.name === name)
    return { name, label: info?.label ?? name, available: info?.available ?? false, detail: info?.availability_detail }
  })
  const unavailable = profileScanners.filter((s) => !s.available)

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>Start a scan</DialogTitle>
          <DialogDescription>
            The target must already be an authorized target of this assessment.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          {!assessmentId && (
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
          )}

          <div className="space-y-1.5">
            <Label>Target <span className="text-destructive">*</span></Label>
            <Select value={target} onValueChange={setTarget} disabled={!assessment}>
              <SelectTrigger><SelectValue placeholder="Choose an authorized target" /></SelectTrigger>
              <SelectContent>
                {targets?.map((t) => (
                  <SelectItem key={t.id} value={String(t.id)} disabled={t.status !== "AUTHORIZED"}>
                    {t.name} — {t.value}
                    {t.status !== "AUTHORIZED" ? " (not authorized)" : ""}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {selectedTarget && (
              <p className="font-mono text-[11px] text-muted-foreground">{selectedTarget.value}</p>
            )}
          </div>

          <div className="space-y-2">
            <Label>Scan profile</Label>
            <div className="grid gap-2">
              {profiles?.map((p) => (
                <button
                  key={p.name}
                  type="button"
                  onClick={() => setProfile(p.name)}
                  className={cn(
                    "rounded-lg border p-3 text-left transition-colors",
                    profile === p.name ? "border-primary bg-primary/5" : "hover:bg-accent"
                  )}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-sm font-medium">{p.label}</span>
                    <span className="flex items-center gap-1.5">
                      {p.invasive && (
                        <Badge variant="muted" className="text-[10px]">Active testing</Badge>
                      )}
                      <span className="text-[11px] text-muted-foreground">{p.estimated_duration}</span>
                    </span>
                  </div>
                  <p className="mt-1 text-xs text-muted-foreground">{p.description}</p>
                </button>
              ))}
            </div>
          </div>

          {selectedProfile && (
            <div className="rounded-lg border bg-muted/40 p-3">
              <p className="mb-2 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                Scanners in this profile
              </p>
              <div className="flex flex-wrap gap-1.5">
                {profileScanners.map((scanner) => (
                  <span
                    key={scanner.name}
                    title={scanner.detail}
                    className={cn(
                      "inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-[11px] font-medium ring-1 ring-inset",
                      scanner.available
                        ? "bg-success/10 text-success ring-success/25"
                        : "bg-muted text-muted-foreground ring-border"
                    )}
                  >
                    {scanner.available ? <CheckCircle2 className="h-3 w-3" /> : <XCircle className="h-3 w-3" />}
                    {scanner.label}
                  </span>
                ))}
              </div>
              {unavailable.length > 0 && (
                <p className="mt-2 flex items-start gap-1.5 text-[11px] text-muted-foreground">
                  <AlertTriangle className="mt-px h-3 w-3 shrink-0 text-severity-medium" />
                  {unavailable.length} scanner{unavailable.length === 1 ? " is" : "s are"} not installed and will be
                  skipped. The scan still runs with everything else.
                </p>
              )}
            </div>
          )}

          <label
            className={cn(
              "flex cursor-pointer gap-3 rounded-lg border p-3 transition-colors",
              authorized ? "border-primary/40 bg-primary/5" : "border-dashed"
            )}
          >
            <Checkbox
              checked={authorized}
              onCheckedChange={(checked) => setAuthorized(checked === true)}
              className="mt-0.5"
            />
            <span className="space-y-1">
              <span className="flex items-center gap-1.5 text-sm font-medium">
                <ShieldAlert className="h-4 w-4 text-severity-medium" /> Authorization
              </span>
              <span className="block text-sm text-muted-foreground">“{AUTHORIZATION_STATEMENT}”</span>
            </span>
          </label>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button loading={mutation.isPending} disabled={!valid} onClick={() => mutation.mutate()}>
            <Radar /> Start scan
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}


/* ------------------------------------------------------------ SARIF import */
export function ImportSarifDialog({ open, onOpenChange, assessmentId }: {
  open: boolean
  onOpenChange: (open: boolean) => void
  assessmentId?: number
}) {
  const [assessment, setAssessment] = React.useState(assessmentId ? String(assessmentId) : "")
  const [target, setTarget] = React.useState("")
  const [tool, setTool] = React.useState("semgrep")
  const [file, setFile] = React.useState<File | null>(null)
  const { toast } = useToast()
  const navigate = useNavigate()
  const queryClient = useQueryClient()

  React.useEffect(() => {
    if (open) {
      setAssessment(assessmentId ? String(assessmentId) : "")
      setTarget(""); setTool("semgrep"); setFile(null)
    }
  }, [open, assessmentId])

  const { data: assessments } = useQuery({
    queryKey: ["assessments", "picker"],
    queryFn: () => assessmentApi.list({ page_size: 100 }),
    enabled: open && !assessmentId,
  })
  const { data: targets } = useQuery({
    queryKey: ["assessment-targets", assessment],
    queryFn: () => assessmentApi.targets(Number(assessment)),
    enabled: open && !!assessment,
  })
  const { data: tools } = useQuery({
    queryKey: ["import-tools"], queryFn: scanApi.importTools, enabled: open,
  })

  const mutation = useMutation({
    mutationFn: () => scanApi.importSarif(Number(assessment), Number(target), tool, file!),
    onSuccess: (scan) => {
      toast(
        "success",
        `Imported ${scan.findings_count} findings from ${tool}`,
        scan.duplicates_merged > 0
          ? `${scan.duplicates_merged} correlated with findings you already had.`
          : undefined
      )
      queryClient.invalidateQueries({ queryKey: ["scans"] })
      queryClient.invalidateQueries({ queryKey: ["findings"] })
      queryClient.invalidateQueries({ queryKey: ["dashboard"] })
      onOpenChange(false)
      navigate(`/scans/${scan.id}`)
    },
    onError: (e) => toast("error", "Import failed", errorMessage(e)),
  })

  const valid = assessment && target && tool.trim() && file

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Import scan results (SARIF)</DialogTitle>
          <DialogDescription>
            Upload a SARIF 2.1.0 report from any tool — Semgrep, Trivy, Gitleaks, Snyk,
            Checkov, CodeQL and others. Results are normalized, correlated and scored
            exactly like a scan run here.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          {!assessmentId && (
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
          )}

          <div className="space-y-1.5">
            <Label>Target <span className="text-destructive">*</span></Label>
            <Select value={target} onValueChange={setTarget} disabled={!assessment}>
              <SelectTrigger><SelectValue placeholder="Which target do these results describe?" /></SelectTrigger>
              <SelectContent>
                {targets?.map((t) => (
                  <SelectItem key={t.id} value={String(t.id)} disabled={t.status !== "AUTHORIZED"}>
                    {t.name} — {t.value}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-1.5">
            <Label>Tool <span className="text-destructive">*</span></Label>
            <Select value={tool} onValueChange={setTool}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                {(tools ?? ["semgrep"]).map((t) => (
                  <SelectItem key={t} value={t}>{t}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p className="text-[11px] text-muted-foreground">
              Findings are attributed to <code className="font-mono">imported:{tool}</code> so
              their origin stays explicit.
            </p>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="sarif-file">SARIF file <span className="text-destructive">*</span></Label>
            <Input
              id="sarif-file" type="file" accept=".sarif,.json,application/json"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              className="file:mr-3 file:rounded file:border-0 file:bg-secondary file:px-2 file:py-1 file:text-xs"
            />
            {file && (
              <p className="text-[11px] text-muted-foreground">
                {file.name} · {(file.size / 1024).toFixed(0)} KB
              </p>
            )}
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button loading={mutation.isPending} disabled={!valid} onClick={() => mutation.mutate()}>
            <Upload /> Import results
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
