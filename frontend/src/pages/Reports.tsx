import * as React from "react"
import { useQuery } from "@tanstack/react-query"
import { Download, FileText } from "lucide-react"
import { reportApi } from "@/services/endpoints"
import { downloadFile } from "@/services/api"
import { PageHeader } from "@/layouts/AppLayout"
import { Card } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge, StatusBadge } from "@/components/ui/badge"
import { EmptyState, ErrorState, TableSkeleton, Tooltip } from "@/components/ui/misc"
import { Pagination, Table, TBody, TD, TH, THead, TR } from "@/components/ui/table"
import { GenerateReportDialog } from "@/components/report-dialogs"
import { errorMessage, useToast } from "@/components/ui/toast"
import { formatBytes, relativeTime } from "@/lib/utils"
import { useAuth } from "@/hooks/useAuth"

export default function ReportsPage() {
  const { can } = useAuth()
  const { toast } = useToast()
  const [page, setPage] = React.useState(1)
  const [open, setOpen] = React.useState(false)

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["reports", { page }],
    queryFn: () => reportApi.list({ page, page_size: 25 }),
  })

  async function handleDownload(id: number, filename: string) {
    try {
      await downloadFile(`/reports/${id}/download`, filename)
    } catch (err) {
      toast("error", "Download failed", errorMessage(err))
    }
  }

  return (
    <>
      <PageHeader
        title="Reports"
        description="Generated assessment reports covering scope, findings, evidence, remediation and retests."
        actions={can("report:create") ? <Button onClick={() => setOpen(true)}><FileText /> Generate report</Button> : null}
      />

      <Card className="overflow-hidden">
        {isLoading ? (
          <TableSkeleton rows={5} cols={6} />
        ) : error ? (
          <ErrorState error={error} onRetry={refetch} />
        ) : !data?.items?.length ? (
          <EmptyState
            icon={FileText}
            title="No reports yet"
            description="Generate a PDF, CSV or JSON report from any assessment."
            action={can("report:create") ? <Button onClick={() => setOpen(true)}><FileText /> Generate report</Button> : null}
          />
        ) : (
          <>
            <Table>
              <THead>
                <TR>
                  <TH>Reference</TH><TH>Title</TH><TH>Assessment</TH><TH>Format</TH>
                  <TH>Status</TH><TH>Size</TH><TH>Generated</TH><TH className="w-24" />
                </TR>
              </THead>
              <TBody>
                {data?.items.map((report) => (
                  <TR key={report.id}>
                    <TD className="font-mono text-xs">{report.reference}</TD>
                    <TD className="font-medium">{report.title}</TD>
                    <TD className="text-sm text-muted-foreground">{report.assessment_name ?? "—"}</TD>
                    <TD>
                      <Tooltip label={report.engine ? `Rendered with ${report.engine}` : undefined}>
                        <Badge variant="muted">{report.format}</Badge>
                      </Tooltip>
                    </TD>
                    <TD><StatusBadge status={report.status === "READY" ? "COMPLETED" : report.status} /></TD>
                    <TD className="text-xs text-muted-foreground">{formatBytes(report.size_bytes)}</TD>
                    <TD className="whitespace-nowrap text-xs text-muted-foreground">
                      {relativeTime(report.created_at)}
                      {report.generated_by && (
                        <span className="block">by {report.generated_by.full_name}</span>
                      )}
                    </TD>
                    <TD>
                      {report.status === "READY" && can("report:download") && (
                        <Button
                          variant="ghost" size="sm"
                          onClick={() => handleDownload(report.id, report.filename ?? `${report.reference}.${report.format.toLowerCase()}`)}
                        >
                          <Download /> Download
                        </Button>
                      )}
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

      <GenerateReportDialog open={open} onOpenChange={setOpen} />
    </>
  )
}
