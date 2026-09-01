import * as React from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { AlertTriangle, CheckCircle2, ShieldAlert } from "lucide-react"
import { assessmentApi, assetApi } from "@/services/endpoints"
import { Button } from "@/components/ui/button"
import { Input, Textarea } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Checkbox } from "@/components/ui/misc"
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { errorMessage, useToast } from "@/components/ui/toast"
import { cn } from "@/lib/utils"

export const AUTHORIZATION_STATEMENT =
  "I confirm that I am authorized to perform security testing against this target."

export function AddTargetDialog({ open, onOpenChange, assessmentId }: {
  open: boolean
  onOpenChange: (open: boolean) => void
  assessmentId: number
}) {
  const [name, setName] = React.useState("")
  const [type, setType] = React.useState("WEB_APP")
  const [value, setValue] = React.useState("")
  const [description, setDescription] = React.useState("")
  const [assetId, setAssetId] = React.useState("")
  const [authorized, setAuthorized] = React.useState(false)
  const { toast } = useToast()
  const queryClient = useQueryClient()

  React.useEffect(() => {
    if (open) {
      setName(""); setType("WEB_APP"); setValue(""); setDescription("")
      setAssetId(""); setAuthorized(false)
    }
  }, [open])

  const { data: assets } = useQuery({
    queryKey: ["assets", "picker"],
    queryFn: () => assetApi.list({ page_size: 100 }),
    enabled: open,
  })

  // Live scope feedback before the user even submits.
  const scopeCheck = useQuery({
    queryKey: ["scope-check", assessmentId, value],
    queryFn: () => assessmentApi.checkScope(assessmentId, value),
    enabled: open && value.trim().length > 3,
    retry: false,
  })

  const mutation = useMutation({
    mutationFn: () =>
      assessmentApi.addTarget(assessmentId, {
        name, target_type: type, value,
        description: description || undefined,
        asset_id: assetId ? Number(assetId) : undefined,
        authorization_confirmed: authorized,
      }),
    onSuccess: (target) => {
      toast("success", "Target added", `${target.reference} is authorized and ready to scan.`)
      queryClient.invalidateQueries({ queryKey: ["assessment-targets"] })
      queryClient.invalidateQueries({ queryKey: ["assessment", assessmentId] })
      queryClient.invalidateQueries({ queryKey: ["targets"] })
      onOpenChange(false)
    },
    onError: (e) => toast("error", "Could not add the target", errorMessage(e)),
  })

  const valid = name.trim().length >= 2 && value.trim().length >= 3 && authorized

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add an authorized target</DialogTitle>
          <DialogDescription>
            A target must fall inside this assessment's authorized scope, and you must
            confirm you are permitted to test it.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="t-name">Name <span className="text-destructive">*</span></Label>
              <Input id="t-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Student Portal" />
            </div>
            <div className="space-y-1.5">
              <Label>Type</Label>
              <Select value={type} onValueChange={setType}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="WEB_APP">Web application</SelectItem>
                  <SelectItem value="REST_API">REST API</SelectItem>
                  <SelectItem value="HOST">Host / IP</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="t-value">URL, hostname or IP <span className="text-destructive">*</span></Label>
            <Input
              id="t-value" value={value} onChange={(e) => setValue(e.target.value)}
              placeholder="https://portal.example.edu" className="font-mono text-sm"
            />
            {value.trim().length > 3 && scopeCheck.data && (
              <div
                className={cn(
                  "flex items-start gap-2 rounded-md border p-2.5 text-xs",
                  scopeCheck.data.in_scope
                    ? "border-success/30 bg-success/10"
                    : "border-destructive/30 bg-destructive/10"
                )}
              >
                {scopeCheck.data.in_scope ? (
                  <CheckCircle2 className="mt-px h-3.5 w-3.5 shrink-0 text-success" />
                ) : (
                  <AlertTriangle className="mt-px h-3.5 w-3.5 shrink-0 text-destructive" />
                )}
                <span>{scopeCheck.data.reason}</span>
              </div>
            )}
          </div>

          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label>Linked asset</Label>
              <Select value={assetId} onValueChange={setAssetId}>
                <SelectTrigger><SelectValue placeholder="Optional" /></SelectTrigger>
                <SelectContent>
                  {assets?.items.map((asset) => (
                    <SelectItem key={asset.id} value={String(asset.id)}>{asset.name}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-[11px] text-muted-foreground">
                Asset context drives the contextual risk score.
              </p>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="t-desc">Description</Label>
              <Textarea id="t-desc" rows={2} value={description} onChange={(e) => setDescription(e.target.value)} />
            </div>
          </div>

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
                <ShieldAlert className="h-4 w-4 text-severity-medium" />
                Authorization required
              </span>
              <span className="block text-sm text-muted-foreground">“{AUTHORIZATION_STATEMENT}”</span>
              <span className="block text-[11px] text-muted-foreground">
                This confirmation is recorded against your account in the audit log.
              </span>
            </span>
          </label>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button loading={mutation.isPending} disabled={!valid} onClick={() => mutation.mutate()}>
            Add target
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
