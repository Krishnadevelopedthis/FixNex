import * as React from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { FileText } from "lucide-react"
import { assessmentApi, reportApi } from "@/services/endpoints"
import { downloadFile } from "@/services/api"
import { Button } from "@/components/ui/button"
import { Label } from "@/components/ui/label"
import { Checkbox } from "@/components/ui/misc"
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { errorMessage, useToast } from "@/components/ui/toast"
import { cn } from "@/lib/utils"

const FORMATS = [
  { value: "PDF", label: "PDF", hint: "Formatted report for stakeholders" },
  { value: "CSV", label: "CSV", hint: "Findings table for spreadsheets" },
  { value: "JSON", label: "JSON", hint: "Full structured export" },
  { value: "XLSX", label: "XLSX", hint: "Excel workbook" },
  { value: "HTML", label: "HTML", hint: "Self-contained web page" },
]

export function GenerateReportDialog({ open, onOpenChange, assessmentId }: {
  open: boolean
  onOpenChange: (open: boolean) => void
  assessmentId?: number
}) {
  const [assessment, setAssessment] = React.useState(assessmentId ? String(assessmentId) : "")
  const [format, setFormat] = React.useState("PDF")
  const [includeFalsePositives, setIncludeFalsePositives] = React.useState(false)
  const [includeInformational, setIncludeInformational] = React.useState(true)
  const [includeEvidence, setIncludeEvidence] = React.useState(true)
  const [includeRetest, setIncludeRetest] = React.useState(true)
  const { toast } = useToast()
  const queryClient = useQueryClient()

  React.useEffect(() => {
    if (open) {
      setAssessment(assessmentId ? String(assessmentId) : "")
      setFormat("PDF")
    }
  }, [open, assessmentId])

  const { data: assessments } = useQuery({
    queryKey: ["assessments", "picker"],
    queryFn: () => assessmentApi.list({ page_size: 100 }),
    enabled: open && !assessmentId,
  })

  const mutation = useMutation({
    mutationFn: () =>
      reportApi.create({
        assessment_id: Number(assessment),
        format,
        include_false_positives: includeFalsePositives,
        include_informational: includeInformational,
        include_evidence: includeEvidence,
        include_retest: includeRetest,
      }),
    onSuccess: async (report) => {
      toast("success", "Report generated", `${report.filename ?? report.reference} is ready.`)
      queryClient.invalidateQueries({ queryKey: ["reports"] })
      onOpenChange(false)
      try {
        await downloadFile(`/reports/${report.id}/download`, report.filename ?? `${report.reference}.${format.toLowerCase()}`)
      } catch (error) {
        toast("error", "Report created but the download failed", errorMessage(error))
      }
    },
    onError: (e) => toast("error", "Could not generate the report", errorMessage(e)),
  })

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Generate report</DialogTitle>
          <DialogDescription>
            Produces a report covering scope, methodology, findings, evidence, remediation and retest results.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          {!assessmentId && (
            <div className="space-y-1.5">
              <Label>Assessment <span className="text-destructive">*</span></Label>
              <Select value={assessment} onValueChange={setAssessment}>
                <SelectTrigger><SelectValue placeholder="Choose an assessment" /></SelectTrigger>
                <SelectContent>
                  {assessments?.items.map((a) => (
                    <SelectItem key={a.id} value={String(a.id)}>{a.name}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )}

          <div className="space-y-2">
            <Label>Format</Label>
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
              {FORMATS.map((f) => (
                <button
                  key={f.value}
                  type="button"
                  onClick={() => setFormat(f.value)}
                  className={cn(
                    "rounded-lg border p-2.5 text-left transition-colors",
                    format === f.value ? "border-primary bg-primary/5" : "hover:bg-accent"
                  )}
                >
                  <span className="block text-sm font-medium">{f.label}</span>
                  <span className="block text-[11px] text-muted-foreground">{f.hint}</span>
                </button>
              ))}
            </div>
          </div>

          <div className="space-y-2">
            <Label>Contents</Label>
            {[
              { label: "Include informational findings", value: includeInformational, set: setIncludeInformational },
              { label: "Include evidence inventory", value: includeEvidence, set: setIncludeEvidence },
              { label: "Include retest results", value: includeRetest, set: setIncludeRetest },
              { label: "Include false positives (with justifications)", value: includeFalsePositives, set: setIncludeFalsePositives },
            ].map((option) => (
              <label key={option.label} className="flex cursor-pointer items-center gap-2.5 text-sm">
                <Checkbox
                  checked={option.value}
                  onCheckedChange={(checked) => option.set(checked === true)}
                />
                {option.label}
              </label>
            ))}
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button loading={mutation.isPending} disabled={!assessment} onClick={() => mutation.mutate()}>
            <FileText /> Generate &amp; download
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
