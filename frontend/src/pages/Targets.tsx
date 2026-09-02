import * as React from "react"
import { Link } from "react-router-dom"
import { useQuery } from "@tanstack/react-query"
import { Crosshair, Radar, ShieldCheck } from "lucide-react"
import { targetApi } from "@/services/endpoints"
import { PageHeader } from "@/layouts/AppLayout"
import { Card } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge, DemoBadge, StatusBadge } from "@/components/ui/badge"
import { EmptyState, ErrorState, TableSkeleton, Tooltip } from "@/components/ui/misc"
import { Pagination, Table, TBody, TD, TH, THead, TR } from "@/components/ui/table"
import { NewScanDialog } from "@/components/scan-dialogs"
import { relativeTime, titleCase } from "@/lib/utils"
import { useAuth } from "@/hooks/useAuth"

export default function TargetsPage() {
  const { can } = useAuth()
  const [page, setPage] = React.useState(1)
  const [scanTarget, setScanTarget] = React.useState<{ id: number; assessmentId: number } | null>(null)

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["targets", { page }],
    queryFn: () => targetApi.list({ page, page_size: 25 }),
  })

  return (
    <>
      <PageHeader
        title="Targets"
        description="Authorized testing targets across every assessment. Targets are added from within an assessment's scope."
      />

      <Card className="overflow-hidden">
        {isLoading ? (
          <TableSkeleton rows={6} cols={7} />
        ) : error ? (
          <ErrorState error={error} onRetry={refetch} />
        ) : !data?.items?.length ? (
          <EmptyState
            icon={Crosshair}
            title="No targets yet"
            description="Open an assessment and add a target that falls inside its authorized scope."
          />
        ) : (
          <>
            <Table>
              <THead>
                <TR>
                  <TH>Reference</TH><TH>Name</TH><TH>Type</TH><TH>Value</TH>
                  <TH>Status</TH><TH>Findings</TH><TH>Last scan</TH><TH className="w-20" />
                </TR>
              </THead>
              <TBody>
                {data?.items.map((target) => (
                  <TR key={target.id}>
                    <TD className="font-mono text-xs">{target.reference}</TD>
                    <TD>
                      <div className="flex items-center gap-2">
                        <span className="font-medium">{target.name}</span>
                        {target.is_demo && <DemoBadge />}
                      </div>
                      {target.asset_name && (
                        <p className="text-[11px] text-muted-foreground">{target.asset_name}</p>
                      )}
                    </TD>
                    <TD><Badge variant="muted">{titleCase(target.target_type)}</Badge></TD>
                    <TD className="max-w-xs truncate font-mono text-xs">{target.value}</TD>
                    <TD>
                      <div className="flex items-center gap-1.5">
                        <StatusBadge status={target.status} />
                        {target.authorization_confirmed && (
                          <Tooltip label={`Authorized by ${target.authorized_by?.full_name ?? "—"}`}>
                            <ShieldCheck className="h-3.5 w-3.5 text-success" />
                          </Tooltip>
                        )}
                      </div>
                    </TD>
                    <TD>{target.findings_count}</TD>
                    <TD className="whitespace-nowrap text-xs text-muted-foreground">
                      {target.last_scan_at ? relativeTime(target.last_scan_at) : "Never"}
                    </TD>
                    <TD>
                      <div className="flex items-center gap-1">
                        <Link to={`/assessments/${target.assessment_id}`}>
                          <Button variant="ghost" size="sm">Open</Button>
                        </Link>
                        {can("scan:create") && target.status === "AUTHORIZED" && (
                          <Tooltip label="Scan this target">
                            <Button
                              variant="ghost" size="icon-sm"
                              onClick={() => setScanTarget({ id: target.id, assessmentId: target.assessment_id })}
                            >
                              <Radar className="h-4 w-4" />
                            </Button>
                          </Tooltip>
                        )}
                      </div>
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
            {data && (
              <Pagination page={data.page} pages={data.pages} total={data.total} pageSize={data.page_size} onPage={setPage} />
            )}
          </>
        )}
      </Card>

      <NewScanDialog
        open={!!scanTarget}
        onOpenChange={(open) => !open && setScanTarget(null)}
        assessmentId={scanTarget?.assessmentId}
        targetId={scanTarget?.id}
      />
    </>
  )
}
