import * as React from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Plus, Server } from "lucide-react"
import { assetApi } from "@/services/endpoints"
import { PageHeader } from "@/layouts/AppLayout"
import { Card, CardContent } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input, Textarea } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Badge, DemoBadge, SeverityBadge } from "@/components/ui/badge"
import { EmptyState, ErrorState, Skeleton } from "@/components/ui/misc"
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { errorMessage, useToast } from "@/components/ui/toast"
import { titleCase } from "@/lib/utils"
import { useAuth } from "@/hooks/useAuth"

const CRITICALITY = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
const SENSITIVITY = ["HIGH", "MEDIUM", "LOW", "NONE"]
const EXPOSURE = ["INTERNET_FACING", "INTERNAL", "ISOLATED"]
const TYPES = ["WEB_APPLICATION", "REST_API", "SERVER", "NETWORK_DEVICE", "DATABASE", "OTHER"]

function NewAssetDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const [form, setForm] = React.useState({
    name: "", description: "", asset_type: "WEB_APPLICATION", owner: "",
    primary_url: "", criticality: "MEDIUM", data_sensitivity: "MEDIUM", exposure: "INTERNAL",
  })
  const { toast } = useToast()
  const queryClient = useQueryClient()

  React.useEffect(() => {
    if (open) setForm({
      name: "", description: "", asset_type: "WEB_APPLICATION", owner: "",
      primary_url: "", criticality: "MEDIUM", data_sensitivity: "MEDIUM", exposure: "INTERNAL",
    })
  }, [open])

  const mutation = useMutation({
    mutationFn: () => assetApi.create(form),
    onSuccess: () => {
      toast("success", "Asset created")
      queryClient.invalidateQueries({ queryKey: ["assets"] })
      onOpenChange(false)
    },
    onError: (e) => toast("error", "Could not create the asset", errorMessage(e)),
  })

  const set = (key: string) => (value: string) => setForm((f) => ({ ...f, [key]: value }))

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New asset</DialogTitle>
          <DialogDescription>
            Asset context — criticality, data sensitivity and exposure — is what turns a raw
            CVSS score into a meaningful contextual risk score.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="as-name">Name <span className="text-destructive">*</span></Label>
            <Input id="as-name" value={form.name} onChange={(e) => set("name")(e.target.value)} />
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label>Type</Label>
              <Select value={form.asset_type} onValueChange={set("asset_type")}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  {TYPES.map((t) => <SelectItem key={t} value={t}>{titleCase(t)}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="as-owner">Owner</Label>
              <Input id="as-owner" value={form.owner} onChange={(e) => set("owner")(e.target.value)} placeholder="IT Department" />
            </div>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="as-url">Primary URL</Label>
            <Input id="as-url" value={form.primary_url} onChange={(e) => set("primary_url")(e.target.value)} className="font-mono text-sm" />
          </div>
          <div className="grid gap-3 sm:grid-cols-3">
            <div className="space-y-1.5">
              <Label>Criticality</Label>
              <Select value={form.criticality} onValueChange={set("criticality")}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>{CRITICALITY.map((v) => <SelectItem key={v} value={v}>{titleCase(v)}</SelectItem>)}</SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label>Data sensitivity</Label>
              <Select value={form.data_sensitivity} onValueChange={set("data_sensitivity")}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>{SENSITIVITY.map((v) => <SelectItem key={v} value={v}>{titleCase(v)}</SelectItem>)}</SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label>Exposure</Label>
              <Select value={form.exposure} onValueChange={set("exposure")}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>{EXPOSURE.map((v) => <SelectItem key={v} value={v}>{titleCase(v)}</SelectItem>)}</SelectContent>
              </Select>
            </div>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="as-desc">Description</Label>
            <Textarea id="as-desc" rows={2} value={form.description} onChange={(e) => set("description")(e.target.value)} />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button loading={mutation.isPending} disabled={form.name.trim().length < 2} onClick={() => mutation.mutate()}>
            Create asset
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

export default function AssetsPage() {
  const { can } = useAuth()
  const [open, setOpen] = React.useState(false)
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["assets"],
    queryFn: () => assetApi.list({ page_size: 60 }),
  })

  return (
    <>
      <PageHeader
        title="Assets"
        description="The business systems under assessment. Their context drives contextual risk scoring."
        actions={can("asset:create") ? <Button onClick={() => setOpen(true)}><Plus /> New asset</Button> : null}
      />

      {isLoading ? (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-48" />)}
        </div>
      ) : error ? (
        <Card><ErrorState error={error} onRetry={refetch} /></Card>
      ) : !data?.items?.length ? (
        <Card>
          <EmptyState
            icon={Server}
            title="No assets yet"
            description="Register the systems you assess so findings inherit real business context."
            action={can("asset:create") ? <Button onClick={() => setOpen(true)}><Plus /> New asset</Button> : null}
          />
        </Card>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {data?.items.map((asset) => (
            <Card key={asset.id}>
              <CardContent className="space-y-3 p-5">
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <p className="font-mono text-[11px] text-muted-foreground">{asset.reference}</p>
                    <p className="line-clamp-2 font-semibold leading-tight">{asset.name}</p>
                  </div>
                  <SeverityBadge severity={asset.criticality} showDot={false} />
                </div>

                {asset.primary_url && (
                  <p className="truncate font-mono text-[11px] text-muted-foreground">{asset.primary_url}</p>
                )}

                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div>
                    <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Sensitivity</p>
                    <p className="font-medium">{titleCase(asset.data_sensitivity)}</p>
                  </div>
                  <div>
                    <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Exposure</p>
                    <p className="font-medium">{titleCase(asset.exposure)}</p>
                  </div>
                </div>

                {asset.technologies?.length > 0 && (
                  <div className="flex flex-wrap gap-1">
                    {asset.technologies.slice(0, 5).map((tech: any, i: number) => (
                      <Badge key={i} variant="muted" className="text-[10px]">
                        {tech.name}{tech.version ? ` ${tech.version}` : ""}
                      </Badge>
                    ))}
                  </div>
                )}

                <div className="flex items-center justify-between border-t pt-2.5 text-[11px] text-muted-foreground">
                  <span>{asset.owner ?? "Unassigned owner"}</span>
                  <span className="flex items-center gap-1.5">
                    {asset.open_findings > 0 && (
                      <Badge variant="muted">{asset.open_findings} open</Badge>
                    )}
                    {asset.is_demo && <DemoBadge />}
                  </span>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      <NewAssetDialog open={open} onOpenChange={setOpen} />
    </>
  )
}
