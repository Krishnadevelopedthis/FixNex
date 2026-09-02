import * as React from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Plus, Trash2, Users as UsersIcon } from "lucide-react"
import { userApi } from "@/services/endpoints"
import { PageHeader } from "@/layouts/AppLayout"
import { Card } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Badge } from "@/components/ui/badge"
import { ConfirmDialog } from "@/components/ui/confirm"
import { EmptyState, ErrorState, TableSkeleton } from "@/components/ui/misc"
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table"
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { errorMessage, useToast } from "@/components/ui/toast"
import { relativeTime, titleCase } from "@/lib/utils"
import { useAuth } from "@/hooks/useAuth"

const ROLES = ["ADMIN", "SECURITY_LEAD", "SECURITY_ENGINEER", "ANALYST", "DEVELOPER", "VIEWER"]

export default function UsersPage() {
  const { can, user: me } = useAuth()
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [createOpen, setCreateOpen] = React.useState(false)
  const [deleting, setDeleting] = React.useState<{ id: number; name: string } | null>(null)
  const [form, setForm] = React.useState({ email: "", full_name: "", password: "", role: "VIEWER", job_title: "" })

  const { data, isLoading, error, refetch } = useQuery({ queryKey: ["users", "all"], queryFn: () => userApi.list(false) })

  React.useEffect(() => {
    if (createOpen) setForm({ email: "", full_name: "", password: "", role: "VIEWER", job_title: "" })
  }, [createOpen])

  const createMutation = useMutation({
    mutationFn: () => userApi.create(form),
    onSuccess: () => {
      toast("success", "User created")
      queryClient.invalidateQueries({ queryKey: ["users"] })
      setCreateOpen(false)
    },
    onError: (e) => toast("error", "Could not create the user", errorMessage(e)),
  })

  const roleMutation = useMutation({
    mutationFn: ({ id, role }: { id: number; role: string }) => userApi.update(id, { role }),
    onSuccess: () => {
      toast("success", "Role updated")
      queryClient.invalidateQueries({ queryKey: ["users"] })
    },
    onError: (e) => toast("error", "Could not change the role", errorMessage(e)),
  })

  const activeMutation = useMutation({
    mutationFn: ({ id, is_active }: { id: number; is_active: boolean }) => userApi.update(id, { is_active }),
    onSuccess: () => {
      toast("success", "Account updated")
      queryClient.invalidateQueries({ queryKey: ["users"] })
    },
    onError: (e) => toast("error", "Could not update the account", errorMessage(e)),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: number) => userApi.remove(id),
    onSuccess: () => {
      toast("success", "User removed")
      setDeleting(null)
      queryClient.invalidateQueries({ queryKey: ["users"] })
    },
    onError: (e) => toast("error", "Could not remove the user", errorMessage(e)),
  })

  return (
    <>
      <PageHeader
        title="Users"
        description="Accounts and their platform roles."
        actions={can("user:create") ? <Button onClick={() => setCreateOpen(true)}><Plus /> New user</Button> : null}
      />

      <Card className="overflow-hidden">
        {isLoading ? (
          <TableSkeleton rows={6} cols={6} />
        ) : error ? (
          <ErrorState error={error} onRetry={refetch} />
        ) : !data || data.length === 0 ? (
          <EmptyState icon={UsersIcon} title="No users" />
        ) : (
          <Table>
            <THead>
              <TR>
                <TH>Name</TH><TH>Email</TH><TH className="w-52">Role</TH>
                <TH>Status</TH><TH>Last sign-in</TH><TH className="w-16" />
              </TR>
            </THead>
            <TBody>
              {data.map((account) => (
                <TR key={account.id} className={account.is_active ? undefined : "opacity-60"}>
                  <TD>
                    <div className="flex items-center gap-2">
                      <span className="font-medium">{account.full_name}</span>
                      {account.id === me?.id && <Badge variant="muted" className="text-[10px]">You</Badge>}
                    </div>
                    {account.job_title && (
                      <p className="text-[11px] text-muted-foreground">{account.job_title}</p>
                    )}
                  </TD>
                  <TD className="text-sm text-muted-foreground">{account.email}</TD>
                  <TD>
                    {can("role:manage") && account.id !== me?.id ? (
                      <Select
                        value={account.role}
                        onValueChange={(role) => roleMutation.mutate({ id: account.id, role })}
                      >
                        <SelectTrigger className="h-8"><SelectValue /></SelectTrigger>
                        <SelectContent>
                          {ROLES.map((r) => <SelectItem key={r} value={r}>{titleCase(r)}</SelectItem>)}
                        </SelectContent>
                      </Select>
                    ) : (
                      <Badge variant="muted">{titleCase(account.role)}</Badge>
                    )}
                  </TD>
                  <TD>
                    <div className="flex items-center gap-2">
                      <Badge variant={account.is_active ? "default" : "muted"}>
                        {account.is_active ? "Active" : "Deactivated"}
                      </Badge>
                      {can("user:update") && account.id !== me?.id && (
                        <button
                          onClick={() =>
                            activeMutation.mutate({ id: account.id, is_active: !account.is_active })
                          }
                          className="text-[11px] font-medium text-muted-foreground underline-offset-2 hover:text-primary hover:underline"
                        >
                          {account.is_active ? "Deactivate" : "Reactivate"}
                        </button>
                      )}
                    </div>
                  </TD>
                  <TD className="text-xs text-muted-foreground">
                    {account.last_login_at ? relativeTime(account.last_login_at) : "Never"}
                  </TD>
                  <TD>
                    {can("user:delete") && account.id !== me?.id && (
                      <Button
                        variant="ghost" size="icon-sm"
                        onClick={() => setDeleting({ id: account.id, name: account.full_name })}
                      >
                        <Trash2 className="h-4 w-4 text-destructive" />
                      </Button>
                    )}
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>
        )}
      </Card>

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New user</DialogTitle>
            <DialogDescription>
              The password is hashed with Argon2id and is never stored in plain text.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="u-name">Full name <span className="text-destructive">*</span></Label>
              <Input id="u-name" value={form.full_name} onChange={(e) => setForm({ ...form, full_name: e.target.value })} />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="u-email">Email <span className="text-destructive">*</span></Label>
              <Input id="u-email" type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="u-pass">Password <span className="text-destructive">*</span></Label>
              <Input id="u-pass" type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
              <p className="text-[11px] text-muted-foreground">
                At least 10 characters, with upper case, lower case and a digit.
              </p>
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label>Role</Label>
                <Select value={form.role} onValueChange={(role) => setForm({ ...form, role })}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {ROLES.map((r) => <SelectItem key={r} value={r}>{titleCase(r)}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="u-title">Job title</Label>
                <Input id="u-title" value={form.job_title} onChange={(e) => setForm({ ...form, job_title: e.target.value })} />
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>Cancel</Button>
            <Button
              loading={createMutation.isPending}
              disabled={!form.email || !form.full_name || !form.password}
              onClick={() => createMutation.mutate()}
            >
              Create user
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={!!deleting}
        onOpenChange={(open) => !open && setDeleting(null)}
        title={`Remove ${deleting?.name}?`}
        description="Their audit history is retained; the account can no longer sign in."
        confirmLabel="Remove user"
        loading={deleteMutation.isPending}
        onConfirm={() => deleting && deleteMutation.mutate(deleting.id)}
      />
    </>
  )
}
