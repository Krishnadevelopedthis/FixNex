import * as React from "react"
import { Link } from "react-router-dom"
import { useQuery } from "@tanstack/react-query"
import { Radar, Upload } from "lucide-react"
import { scanApi } from "@/services/endpoints"
import { PageHeader } from "@/layouts/AppLayout"
import { Card } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge, StatusBadge } from "@/components/ui/badge"
import { EmptyState, ErrorState, Progress, TableSkeleton } from "@/components/ui/misc"
import { Pagination, Table, TBody, TD, TH, THead, TR } from "@/components/ui/table"
import { ImportSarifDialog, NewScanDialog } from "@/components/scan-dialogs"
import { relativeTime, titleCase } from "@/lib/utils"
import { useAuth } from "@/hooks/useAuth"

export default function ScansPage() {
  const { can } = useAuth()
  const [page, setPage] = React.useState(1)
  const [open, setOpen] = React.useState(false)
  const [importOpen, setImportOpen] = React.useState(false)

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["scans", { page }],
    queryFn: () => scanApi.list({ page, page_size: 25 }),
    // Keep the list live while anything is still running.
    refetchInterval: (query) =>
      query.state.data?.items.some((s) => ["RUNNING", "QUEUED"].includes(s.status)) ? 3000 : false,
  })

  return (
    <>
      <PageHeader
        title="Scans"
        description="Every orchestrated scan, and which scanners contributed to it."
        actions={
          can("scan:create") ? (
            <>
              <Button variant="outline" onClick={() => setImportOpen(true)}>
                <Upload /> Import SARIF
              </Button>
              <Button onClick={() => setOpen(true)}><Radar /> New scan</Button>
            </>
          ) : null
        }
      />

      <Card className="overflow-hidden">
        {isLoading ? (
          <TableSkeleton rows={6} cols={7} />
        ) : error ? (
          <ErrorState error={error} onRetry={refetch} />
        ) : data && data.items.length === 0 ? (
          <EmptyState
            icon={Radar}
            title="No scans yet"
            description="Scans run against authorized targets and produce normalized findings."
            action={can("scan:create") ? <Button onClick={() => setOpen(true)}><Radar /> New scan</Button> : null}
          />
        ) : (
          <>
            <Table>
              <THead>
                <TR>
                  <TH>Reference</TH><TH>Target</TH><TH>Profile</TH><TH>Status</TH>
                  <TH className="w-40">Progress</TH><TH>Findings</TH><TH>Started</TH>
                </TR>
              </THead>
              <TBody>
                {data?.items.map((scan) => (
                  <TR key={scan.id}>
                    <TD>
                      <Link to={`/scans/${scan.id}`} className="font-mono text-xs font-medium text-primary hover:underline">
                        {scan.reference}
                      </Link>
                    </TD>
                    <TD>
                      <Link to={`/scans/${scan.id}`} className="font-medium hover:text-primary">
                        {scan.target_name}
                      </Link>
                    </TD>
                    <TD><Badge variant="muted">{titleCase(scan.profile)}</Badge></TD>
                    <TD><StatusBadge status={scan.status} /></TD>
                    <TD>
                      <div className="flex items-center gap-2">
                        <Progress value={scan.progress} className="h-1.5 flex-1" />
                        <span className="w-9 shrink-0 text-right text-[11px] text-muted-foreground">
                          {scan.progress}%
                        </span>
                      </div>
                    </TD>
                    <TD className="font-medium">{scan.findings_count}</TD>
                    <TD className="whitespace-nowrap text-xs text-muted-foreground">
                      {relativeTime(scan.created_at)}
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

      <NewScanDialog open={open} onOpenChange={setOpen} />
      <ImportSarifDialog open={importOpen} onOpenChange={setImportOpen} />
    </>
  )
}
