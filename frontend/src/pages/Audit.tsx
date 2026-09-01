import * as React from "react"
import { useQuery } from "@tanstack/react-query"
import { ClipboardList, Lock, Search } from "lucide-react"
import { auditApi } from "@/services/endpoints"
import { PageHeader } from "@/layouts/AppLayout"
import { Card, CardContent } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { EmptyState, ErrorState, TableSkeleton } from "@/components/ui/misc"
import { Pagination, Table, TBody, TD, TH, THead, TR } from "@/components/ui/table"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { formatDate, titleCase } from "@/lib/utils"

const ALL = "__all__"

export default function AuditPage() {
  const [page, setPage] = React.useState(1)
  const [action, setAction] = React.useState(ALL)
  const [search, setSearch] = React.useState("")
  const [debounced, setDebounced] = React.useState("")

  React.useEffect(() => {
    const timer = setTimeout(() => { setDebounced(search); setPage(1) }, 300)
    return () => clearTimeout(timer)
  }, [search])

  const { data: actions } = useQuery({ queryKey: ["audit-actions"], queryFn: auditApi.actions })
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["audit", { page, action, debounced }],
    queryFn: () =>
      auditApi.list({
        page, page_size: 40,
        action: action !== ALL ? action : undefined,
        search: debounced || undefined,
      }),
  })

  return (
    <>
      <PageHeader
        title="Audit Logs"
        description="Append-only record of every security-relevant action."
      />

      <Card className="mb-4 border-primary/25 bg-primary/5">
        <CardContent className="flex items-start gap-3 p-4">
          <Lock className="mt-0.5 h-4 w-4 shrink-0 text-primary" />
          <div className="space-y-0.5">
            <p className="text-sm font-medium">Audit records are immutable</p>
            <p className="text-sm text-muted-foreground">
              The API exposes no endpoint to edit or delete an audit record, and no role holds
              such a permission. Entries are written once and only ever read back.
            </p>
          </div>
        </CardContent>
      </Card>

      <div className="mb-4 flex flex-col gap-3 sm:flex-row">
        <div className="relative flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={search} onChange={(e) => setSearch(e.target.value)}
            placeholder="Search descriptions, actors or resources…" className="pl-9"
          />
        </div>
        <Select value={action} onValueChange={(v) => { setAction(v); setPage(1) }}>
          <SelectTrigger className="sm:w-64"><SelectValue placeholder="All actions" /></SelectTrigger>
          <SelectContent>
            <SelectItem value={ALL}>All actions</SelectItem>
            {actions?.map((a) => (
              <SelectItem key={a} value={a}>{a}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <Card className="overflow-hidden">
        {isLoading ? (
          <TableSkeleton rows={10} cols={5} />
        ) : error ? (
          <ErrorState error={error} onRetry={refetch} />
        ) : data && data.items.length === 0 ? (
          <EmptyState icon={ClipboardList} title="No audit entries match" />
        ) : (
          <>
            <Table>
              <THead>
                <TR>
                  <TH className="w-44">Timestamp</TH><TH className="w-52">Action</TH>
                  <TH>Description</TH><TH className="w-52">Actor</TH><TH className="w-32">Resource</TH>
                  <TH className="w-28">IP</TH>
                </TR>
              </THead>
              <TBody>
                {data?.items.map((entry) => (
                  <TR key={entry.id}>
                    <TD className="whitespace-nowrap text-xs text-muted-foreground">
                      {formatDate(entry.created_at, true)}
                    </TD>
                    <TD>
                      <Badge variant="muted" className="font-mono text-[10px]">{entry.action}</Badge>
                    </TD>
                    <TD className="text-sm">{entry.description ?? titleCase(entry.action)}</TD>
                    <TD className="text-xs">
                      {entry.actor_email ?? "system"}
                      {entry.actor_role && (
                        <span className="block text-[10px] text-muted-foreground">
                          {titleCase(entry.actor_role)}
                        </span>
                      )}
                    </TD>
                    <TD className="text-xs text-muted-foreground">
                      {entry.resource_type ? `${entry.resource_type} ${entry.resource_id ?? ""}` : "—"}
                    </TD>
                    <TD className="font-mono text-[11px] text-muted-foreground">{entry.ip_address ?? "—"}</TD>
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
    </>
  )
}
