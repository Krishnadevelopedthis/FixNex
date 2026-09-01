import * as React from "react"
import { useMutation, useQueryClient } from "@tanstack/react-query"
import {
  Download, FileText, Image as ImageIcon, Paperclip, ShieldCheck, Trash2, Upload,
} from "lucide-react"
import { evidenceApi, findingApi } from "@/services/endpoints"
import { downloadFile } from "@/services/api"
import { Button } from "@/components/ui/button"
import { Input, Textarea } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Badge } from "@/components/ui/badge"
import { ConfirmDialog } from "@/components/ui/confirm"
import { EmptyState, Separator, Tooltip } from "@/components/ui/misc"
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { errorMessage, useToast } from "@/components/ui/toast"
import { EvidenceAnnotator } from "@/components/evidence-annotator"
import { formatBytes, relativeTime } from "@/lib/utils"
import { useAuth } from "@/hooks/useAuth"
import type { Evidence, FindingDetail } from "@/types"

export function EvidencePanel({ finding }: { finding: FindingDetail }) {
  const { can } = useAuth()
  const { toast } = useToast()
  const queryClient = useQueryClient()

  const [file, setFile] = React.useState<File | null>(null)
  const [description, setDescription] = React.useState("")
  const [supersedes, setSupersedes] = React.useState<number | undefined>()
  const [deleting, setDeleting] = React.useState<Evidence | null>(null)
  const [annotating, setAnnotating] = React.useState<Evidence | null>(null)
  const inputRef = React.useRef<HTMLInputElement>(null)

  function invalidate() {
    queryClient.invalidateQueries({ queryKey: ["finding", finding.id] })
  }

  const uploadMutation = useMutation({
    mutationFn: () => findingApi.uploadEvidence(finding.id, file!, description || undefined, supersedes),
    onSuccess: (created) => {
      toast("success", "Evidence uploaded", `SHA-256 recorded · version ${created.version}`)
      setFile(null); setDescription(""); setSupersedes(undefined)
      if (inputRef.current) inputRef.current.value = ""
      invalidate()
    },
    onError: (e) => toast("error", "Upload failed", errorMessage(e)),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: number) => evidenceApi.remove(id),
    onSuccess: () => { toast("success", "Evidence removed"); setDeleting(null); invalidate() },
    onError: (e) => toast("error", "Could not remove evidence", errorMessage(e)),
  })

  const verifyMutation = useMutation({
    mutationFn: (id: number) => evidenceApi.verify(id),
    onSuccess: (result) =>
      toast(
        result.integrity_verified ? "success" : "error",
        result.integrity_verified ? "Integrity verified" : "Integrity check FAILED",
        result.detail
      ),
    onError: (e) => toast("error", "Could not verify integrity", errorMessage(e)),
  })

  const current = finding.evidence.filter((e) => e.is_current)
  const superseded = finding.evidence.filter((e) => !e.is_current)

  return (
    <div className="space-y-5">
      {can("evidence:upload") && (
        <div className="space-y-3 rounded-lg border border-dashed p-4">
          <p className="flex items-center gap-1.5 text-sm font-medium">
            <Upload className="h-4 w-4" /> Add evidence
          </p>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="ev-file">File</Label>
              <Input
                id="ev-file" ref={inputRef} type="file"
                onChange={(e) => setFile(e.target.files?.[0] ?? null)}
                className="file:mr-3 file:rounded file:border-0 file:bg-secondary file:px-2 file:py-1 file:text-xs"
              />
              <p className="text-[11px] text-muted-foreground">
                Screenshots, request/response captures, text or PDF. Hashed with SHA-256 on upload.
              </p>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="ev-desc">Description</Label>
              <Textarea
                id="ev-desc" rows={2} value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="What does this artefact show?"
              />
            </div>
          </div>
          {supersedes && (
            <p className="text-xs text-muted-foreground">
              This upload will supersede evidence #{supersedes} as a new version.{" "}
              <button className="text-primary hover:underline" onClick={() => setSupersedes(undefined)}>
                Cancel
              </button>
            </p>
          )}
          <Button
            size="sm" disabled={!file} loading={uploadMutation.isPending}
            onClick={() => uploadMutation.mutate()}
          >
            Upload evidence
          </Button>
        </div>
      )}

      {finding.evidence.length === 0 ? (
        <EmptyState
          icon={Paperclip}
          title="No evidence attached"
          description="Attach screenshots or request/response captures to support this finding."
        />
      ) : (
        <div className="space-y-4">
          <EvidenceList
            items={current}
            onDelete={can("evidence:delete") ? setDeleting : undefined}
            onVerify={(id) => verifyMutation.mutate(id)}
            onSupersede={can("evidence:upload") ? setSupersedes : undefined}
            onAnnotate={setAnnotating}
          />

          {superseded.length > 0 && (
            <>
              <Separator />
              <div className="space-y-2">
                <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                  Superseded versions — retained for chain of custody
                </p>
                <EvidenceList items={superseded} muted onVerify={(id) => verifyMutation.mutate(id)} />
              </div>
            </>
          )}
        </div>
      )}

      <ConfirmDialog
        open={!!deleting}
        onOpenChange={(open) => !open && setDeleting(null)}
        title="Remove this evidence?"
        description={
          <span>
            <strong>{deleting?.filename}</strong> will be marked deleted. The metadata and hash
            remain in the audit trail.
          </span>
        }
        confirmLabel="Remove"
        loading={deleteMutation.isPending}
        onConfirm={() => deleting && deleteMutation.mutate(deleting.id)}
      />

      <Dialog open={!!annotating} onOpenChange={(open) => !open && setAnnotating(null)}>
        <DialogContent size="xl">
          <DialogHeader>
            <DialogTitle>Annotate evidence — {annotating?.filename}</DialogTitle>
          </DialogHeader>
          {annotating && (
            <EvidenceAnnotator
              evidence={annotating}
              onSaved={() => { setAnnotating(null); invalidate() }}
            />
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}

function EvidenceList({ items, muted, onDelete, onVerify, onSupersede, onAnnotate }: {
  items: Evidence[]
  muted?: boolean
  onDelete?: (evidence: Evidence) => void
  onVerify?: (id: number) => void
  onSupersede?: (id: number) => void
  onAnnotate?: (evidence: Evidence) => void
}) {
  const { toast } = useToast()

  async function handleDownload(evidence: Evidence) {
    try {
      await downloadFile(`/evidence/${evidence.id}/download`, evidence.filename)
    } catch (error) {
      toast("error", "Download failed", errorMessage(error))
    }
  }

  return (
    <ul className="space-y-2">
      {items.map((evidence) => {
        const isImage = evidence.content_type.startsWith("image/")
        const Icon = isImage ? ImageIcon : FileText
        return (
          <li
            key={evidence.id}
            className={`rounded-lg border p-3 ${muted ? "opacity-60" : ""}`}
          >
            <div className="flex flex-wrap items-start gap-3">
              <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-muted">
                <Icon className="h-4 w-4 text-muted-foreground" />
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="truncate text-sm font-medium">{evidence.filename}</span>
                  <Badge variant="muted" className="text-[10px]">v{evidence.version}</Badge>
                  {evidence.annotations?.length > 0 && (
                    <Badge variant="muted" className="text-[10px]">
                      {evidence.annotations.length} annotation{evidence.annotations.length === 1 ? "" : "s"}
                    </Badge>
                  )}
                </div>
                {evidence.description && (
                  <p className="mt-0.5 text-sm text-muted-foreground">{evidence.description}</p>
                )}
                <p className="mt-1 text-[11px] text-muted-foreground">
                  {formatBytes(evidence.size_bytes)} · uploaded by{" "}
                  {evidence.uploaded_by?.full_name ?? "unknown"} · {relativeTime(evidence.created_at)}
                </p>
                <Tooltip label="SHA-256 recorded at upload; used to prove the file has not changed.">
                  <p className="mt-1 cursor-help break-all font-mono text-[10px] text-muted-foreground">
                    sha256:{evidence.file_hash}
                  </p>
                </Tooltip>
              </div>
              <div className="flex shrink-0 flex-wrap items-center gap-1">
                {onVerify && (
                  <Tooltip label="Verify integrity">
                    <Button variant="ghost" size="icon-sm" onClick={() => onVerify(evidence.id)}>
                      <ShieldCheck className="h-4 w-4" />
                    </Button>
                  </Tooltip>
                )}
                <Tooltip label="Download">
                  <Button variant="ghost" size="icon-sm" onClick={() => handleDownload(evidence)}>
                    <Download className="h-4 w-4" />
                  </Button>
                </Tooltip>
                {onAnnotate && isImage && (
                  <Button variant="ghost" size="sm" onClick={() => onAnnotate(evidence)}>
                    Annotate
                  </Button>
                )}
                {onSupersede && (
                  <Button variant="ghost" size="sm" onClick={() => onSupersede(evidence.id)}>
                    New version
                  </Button>
                )}
                {onDelete && (
                  <Tooltip label="Remove">
                    <Button variant="ghost" size="icon-sm" onClick={() => onDelete(evidence)}>
                      <Trash2 className="h-4 w-4 text-destructive" />
                    </Button>
                  </Tooltip>
                )}
              </div>
            </div>
          </li>
        )
      })}
    </ul>
  )
}
