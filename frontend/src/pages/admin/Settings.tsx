import * as React from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Clock, Database, Save } from "lucide-react"
import { systemApi } from "@/services/endpoints"
import { PageHeader } from "@/layouts/AppLayout"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { SeverityBadge } from "@/components/ui/badge"
import { ConfirmDialog } from "@/components/ui/confirm"
import { ErrorState, Skeleton } from "@/components/ui/misc"
import { errorMessage, useToast } from "@/components/ui/toast"
import { SEVERITIES } from "@/lib/severity"

export default function SettingsPage() {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [values, setValues] = React.useState<Record<string, number>>({})
  const [seedOpen, setSeedOpen] = React.useState(false)

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["sla-settings"],
    queryFn: systemApi.slaSettings,
  })

  React.useEffect(() => { if (data) setValues(data) }, [data])

  const saveMutation = useMutation({
    mutationFn: () => systemApi.updateSla(values),
    onSuccess: () => {
      toast("success", "SLA windows updated", "New deadlines apply to findings assigned from now on.")
      queryClient.invalidateQueries({ queryKey: ["sla-settings"] })
    },
    onError: (e) => toast("error", "Could not save the SLA settings", errorMessage(e)),
  })

  const seedMutation = useMutation({
    mutationFn: systemApi.seedDemo,
    onSuccess: () => {
      toast("success", "Demo dataset reseeded", "All seeded content is labelled as demo data.")
      setSeedOpen(false)
      queryClient.invalidateQueries()
    },
    onError: (e) => toast("error", "Could not seed the demo data", errorMessage(e)),
  })

  if (isLoading) return <><Skeleton className="mb-4 h-9 w-64" /><Skeleton className="h-72" /></>
  if (error || !data) return <Card><ErrorState error={error} onRetry={refetch} /></Card>

  const changed = JSON.stringify(values) !== JSON.stringify(data)

  return (
    <>
      <PageHeader title="Settings" description="Platform configuration." />

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Clock className="h-4 w-4" /> Remediation SLA windows
            </CardTitle>
            <CardDescription>
              How long a team has to remediate a finding, by severity. Deadlines are set when a
              finding is assigned and drive the on-track / due-soon / overdue indicators.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {SEVERITIES.map((severity) => (
              <div key={severity} className="flex items-center gap-3">
                <div className="w-32 shrink-0">
                  <SeverityBadge severity={severity} />
                </div>
                <div className="flex flex-1 items-center gap-2">
                  <Input
                    type="number" min={1} max={8760}
                    value={values[severity] ?? ""}
                    onChange={(e) =>
                      setValues((v) => ({ ...v, [severity]: Number(e.target.value) }))
                    }
                  />
                  <span className="w-28 shrink-0 text-xs text-muted-foreground">
                    hours ({((values[severity] ?? 0) / 24).toFixed(1)} days)
                  </span>
                </div>
              </div>
            ))}
            <Button
              disabled={!changed}
              loading={saveMutation.isPending}
              onClick={() => saveMutation.mutate()}
            >
              <Save /> Save SLA windows
            </Button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Database className="h-4 w-4" /> Demonstration data
            </CardTitle>
            <CardDescription>
              Reseeds the labelled demo assessment, targets and findings. Everything it creates is
              marked as demo data so it is never mistaken for a real scan result.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground">
              Existing demo content is replaced. Real assessments and findings are left untouched.
            </p>
            <Button variant="outline" onClick={() => setSeedOpen(true)}>
              Reseed demo dataset
            </Button>
          </CardContent>
        </Card>
      </div>

      <ConfirmDialog
        open={seedOpen}
        onOpenChange={setSeedOpen}
        title="Reseed the demonstration dataset?"
        description="Existing demo-labelled assessments and findings are removed and recreated. Real data is not affected."
        confirmLabel="Reseed"
        variant="default"
        loading={seedMutation.isPending}
        onConfirm={() => seedMutation.mutate()}
      />
    </>
  )
}
