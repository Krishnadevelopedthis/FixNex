import { useQuery } from "@tanstack/react-query"
import {
  CheckCircle2, Database, HardDrive, Radar, RefreshCw, Server, Sparkles, XCircle, Zap,
} from "lucide-react"
import { scanApi, systemApi } from "@/services/endpoints"
import { PageHeader } from "@/layouts/AppLayout"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { ErrorState, Skeleton } from "@/components/ui/misc"
import { cn } from "@/lib/utils"

const KIND_ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  database: Database, cache: Zap, queue: Zap, storage: HardDrive,
  scanner: Radar, worker: Server, enrichment: Sparkles,
}

export default function SystemPage() {
  const { data, isLoading, error, refetch, isFetching } = useQuery({
    queryKey: ["system-health"],
    queryFn: systemApi.health,
    refetchInterval: 30_000,
  })
  const { data: scanners } = useQuery({ queryKey: ["scanners"], queryFn: scanApi.scanners })

  if (isLoading) return <><Skeleton className="mb-4 h-9 w-64" /><Skeleton className="h-96" /></>
  if (error || !data) return <Card><ErrorState error={error} onRetry={refetch} /></Card>

  const byKind = data.components.reduce<Record<string, typeof data.components>>((acc, component) => {
    (acc[component.kind] ??= []).push(component)
    return acc
  }, {})

  return (
    <>
      <PageHeader
        title="System Health"
        description="Infrastructure and scanner availability. A missing scanner is skipped, never fatal."
        badge={
          data.healthy ? (
            <Badge className="bg-success/12 text-success ring-1 ring-inset ring-success/30">
              All systems operational
            </Badge>
          ) : (
            <Badge variant="muted">
              {data.degraded_components.length} component
              {data.degraded_components.length === 1 ? "" : "s"} degraded
            </Badge>
          )
        }
        actions={
          <Button variant="outline" onClick={() => refetch()} loading={isFetching}>
            <RefreshCw /> Refresh
          </Button>
        }
      />

      <div className="mb-4 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {[
          { label: "Task runner", value: data.task_runner, hint: data.task_runner === "celery" ? "Celery + Redis" : "In-process threads" },
          { label: "Evidence storage", value: data.storage_backend, hint: data.storage_backend === "minio" ? "MinIO object store" : "Local filesystem" },
          { label: "Enrichment", value: data.offline_mode ? "Offline" : "Online", hint: data.offline_mode ? "External APIs disabled" : "NVD / SSL Labs reachable" },
          { label: "Version", value: data.version, hint: data.demo_mode ? "Demo mode enabled" : "Demo mode off" },
        ].map((item) => (
          <Card key={item.label}>
            <CardContent className="p-4">
              <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                {item.label}
              </p>
              <p className="text-lg font-semibold capitalize">{item.value}</p>
              <p className="text-[11px] text-muted-foreground">{item.hint}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        {Object.entries(byKind).map(([kind, components]) => {
          const Icon = KIND_ICONS[kind] ?? Server
          return (
            <Card key={kind}>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 capitalize">
                  <Icon className="h-4 w-4" /> {kind}
                </CardTitle>
              </CardHeader>
              <CardContent className="p-0">
                <ul className="divide-y">
                  {components.map((component) => (
                    <li key={component.name} className="flex items-start gap-3 px-5 py-3">
                      {component.available ? (
                        <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-success" />
                      ) : (
                        <XCircle className={cn(
                          "mt-0.5 h-4 w-4 shrink-0",
                          component.required ? "text-severity-critical" : "text-muted-foreground"
                        )} />
                      )}
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="text-sm font-medium">{component.label}</span>
                          {component.required && !component.available && (
                            <Badge variant="destructive" className="text-[10px]">Required</Badge>
                          )}
                          {component.version && (
                            <Badge variant="muted" className="text-[10px]">{component.version}</Badge>
                          )}
                        </div>
                        <p className="mt-0.5 text-xs text-muted-foreground">{component.detail}</p>
                      </div>
                    </li>
                  ))}
                </ul>
              </CardContent>
            </Card>
          )
        })}
      </div>

      {scanners && (
        <Card className="mt-4">
          <CardHeader>
            <CardTitle>Scanner adapters</CardTitle>
            <CardDescription>
              Built-in adapters are always available. External tools are detected at runtime;
              when one is missing it is skipped and the scan still completes.
            </CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <ul className="divide-y">
              {scanners.map((scanner) => (
                <li key={scanner.name} className="flex items-start gap-3 px-5 py-3">
                  {scanner.available ? (
                    <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-success" />
                  ) : (
                    <XCircle className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" />
                  )}
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-sm font-medium">{scanner.label}</span>
                      <Badge variant="muted" className="text-[10px]">{scanner.kind}</Badge>
                      {scanner.version && (
                        <span className="font-mono text-[10px] text-muted-foreground">{scanner.version}</span>
                      )}
                    </div>
                    <p className="mt-0.5 text-xs text-muted-foreground">{scanner.description}</p>
                    {!scanner.available && (
                      <p className="mt-0.5 text-xs text-severity-medium">{scanner.availability_detail}</p>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}
    </>
  )
}
