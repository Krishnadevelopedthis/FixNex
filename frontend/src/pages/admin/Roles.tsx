import * as React from "react"
import { useQuery } from "@tanstack/react-query"
import { Check, ShieldCheck, X } from "lucide-react"
import { userApi } from "@/services/endpoints"
import { PageHeader } from "@/layouts/AppLayout"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { ErrorState, Skeleton } from "@/components/ui/misc"
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table"
import { titleCase } from "@/lib/utils"

export default function RolesPage() {
  const { data, isLoading, error, refetch } = useQuery({ queryKey: ["roles"], queryFn: userApi.roles })

  if (isLoading) return <><Skeleton className="mb-4 h-9 w-64" /><Skeleton className="h-96" /></>
  if (error || !data) return <Card><ErrorState error={error} onRetry={refetch} /></Card>

  // Build the full permission list from every role, grouped by resource.
  const allPermissions = Array.from(new Set(data.flatMap((r) => r.permissions))).sort()
  const groups = allPermissions.reduce<Record<string, string[]>>((acc, permission) => {
    const [resource] = permission.split(":")
    ;(acc[resource] ??= []).push(permission)
    return acc
  }, {})

  return (
    <>
      <PageHeader
        title="Roles & Permissions"
        description="Every role's exact capabilities, resolved from the platform's central permission matrix."
      />

      <div className="mb-4 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {data.map((role) => (
          <Card key={role.role}>
            <CardHeader>
              <div className="flex items-center justify-between gap-2">
                <CardTitle className="text-sm">{role.label}</CardTitle>
                <Badge variant="muted" className="font-mono text-[10px]">{role.role}</Badge>
              </div>
              <CardDescription>{role.description}</CardDescription>
            </CardHeader>
            <CardContent>
              <p className="text-xs text-muted-foreground">
                <span className="font-semibold text-foreground">{role.permissions.length}</span> permissions
              </p>
            </CardContent>
          </Card>
        ))}
      </div>

      <Card className="overflow-hidden">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4" /> Permission matrix
          </CardTitle>
          <CardDescription>
            Routes depend on a permission, never on a role name — this table is the single
            source of truth the API enforces.
          </CardDescription>
        </CardHeader>
        <Table>
          <THead>
            <TR>
              <TH className="sticky left-0 bg-card">Permission</TH>
              {data.map((role) => (
                <TH key={role.role} className="text-center">{role.label}</TH>
              ))}
            </TR>
          </THead>
          <TBody>
            {Object.entries(groups).map(([resource, permissions]) => (
              <React.Fragment key={resource}>
                <TR className="bg-muted/50 hover:bg-muted/50">
                  <TD colSpan={data.length + 1} className="py-1.5">
                    <span className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                      {titleCase(resource)}
                    </span>
                  </TD>
                </TR>
                {permissions.map((permission) => (
                  <TR key={permission}>
                    <TD className="sticky left-0 bg-card font-mono text-xs">{permission}</TD>
                    {data.map((role) => {
                      const has = role.permissions.includes(permission)
                      return (
                        <TD key={role.role} className="text-center">
                          {has ? (
                            <Check className="mx-auto h-4 w-4 text-success" />
                          ) : (
                            <X className="mx-auto h-4 w-4 text-muted-foreground/30" />
                          )}
                        </TD>
                      )
                    })}
                  </TR>
                ))}
              </React.Fragment>
            ))}
          </TBody>
        </Table>
      </Card>
    </>
  )
}
