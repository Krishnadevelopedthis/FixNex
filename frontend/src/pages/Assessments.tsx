import * as React from "react"
import { Link } from "react-router-dom"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { CalendarDays, FolderKanban, Plus, Search, Users } from "lucide-react"
import { assessmentApi } from "@/services/endpoints"
import { PageHeader } from "@/layouts/AppLayout"
import { Card, CardContent } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input, Textarea } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Badge, DemoBadge, StatusBadge } from "@/components/ui/badge"
import { EmptyState, ErrorState, Progress, Skeleton } from "@/components/ui/misc"
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog"
import { errorMessage, useToast } from "@/components/ui/toast"
import { SEVERITY_DOT } from "@/lib/severity"
import { cn, formatDate } from "@/lib/utils"
import { useAuth } from "@/hooks/useAuth"
import { motion } from "motion/react"
import { TRANSITION, fadeUp, useEnterOnce, useMotionPrefs } from "@/lib/motion"

function NewAssessmentDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const [name, setName] = React.useState("")
  const [client, setClient] = React.useState("")
  const [description, setDescription] = React.useState("")
  const [startDate, setStartDate] = React.useState("")
  const [endDate, setEndDate] = React.useState("")
  const { toast } = useToast()
  const queryClient = useQueryClient()

  React.useEffect(() => {
    if (open) { setName(""); setClient(""); setDescription(""); setStartDate(""); setEndDate("") }
  }, [open])

  const mutation = useMutation({
    mutationFn: () =>
      assessmentApi.create({
        name,
        client_name: client || undefined,
        description: description || undefined,
        start_date: startDate || undefined,
        end_date: endDate || undefined,
      }),
    onSuccess: (created) => {
      toast("success", "Assessment created", `${created.reference} is ready — define its scope next.`)
      queryClient.invalidateQueries({ queryKey: ["assessments"] })
      queryClient.invalidateQueries({ queryKey: ["dashboard"] })
      onOpenChange(false)
    },
    onError: (e) => toast("error", "Could not create the assessment", errorMessage(e)),
  })

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New assessment</DialogTitle>
          <DialogDescription>
            An assessment holds the authorized scope, targets, scans and findings for one engagement.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="a-name">Name <span className="text-destructive">*</span></Label>
            <Input
              id="a-name" value={name} onChange={(e) => setName(e.target.value)}
              placeholder="College Portal Security Assessment"
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="a-client">Client / project</Label>
            <Input id="a-client" value={client} onChange={(e) => setClient(e.target.value)} />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="a-desc">Description</Label>
            <Textarea id="a-desc" rows={3} value={description} onChange={(e) => setDescription(e.target.value)} />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label htmlFor="a-start">Start date</Label>
              <Input id="a-start" type="date" value={startDate} onChange={(e) => setStartDate(e.target.value)} />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="a-end">End date</Label>
              <Input id="a-end" type="date" value={endDate} onChange={(e) => setEndDate(e.target.value)} />
            </div>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button loading={mutation.isPending} disabled={name.trim().length < 3} onClick={() => mutation.mutate()}>
            Create assessment
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

export default function AssessmentsPage() {
  const { can } = useAuth()
  const [search, setSearch] = React.useState("")
  const [newOpen, setNewOpen] = React.useState(false)
  const { transition, variants, delay } = useMotionPrefs()

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["assessments", { search }],
    queryFn: () => assessmentApi.list({ page_size: 60, search: search || undefined }),
  })
  const enterCards = useEnterOnce(!!data?.items.length)

  return (
    <>
      <PageHeader
        title="Assessments"
        description="Each engagement, its authorized scope and everything discovered within it."
        actions={
          can("assessment:create") ? (
            <Button onClick={() => setNewOpen(true)}><Plus /> New assessment</Button>
          ) : null
        }
      />

      <div className="relative mb-4 max-w-md">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          value={search} onChange={(e) => setSearch(e.target.value)}
          placeholder="Search assessments…" className="pl-9"
        />
      </div>

      {isLoading ? (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-52" />)}
        </div>
      ) : error ? (
        <Card><ErrorState error={error} onRetry={refetch} /></Card>
      ) : data && data.items.length === 0 ? (
        <Card>
          <EmptyState
            icon={FolderKanban}
            title="No assessments yet"
            description="Create an assessment to define an authorized testing scope and start work."
            action={can("assessment:create") ? <Button onClick={() => setNewOpen(true)}><Plus /> New assessment</Button> : null}
          />
        </Card>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {data?.items.map((assessment, index) => {
            const stats = assessment.stats
            const severities = stats?.severity
            return (
              <motion.div
                key={assessment.id}
                variants={variants(fadeUp)}
                initial={enterCards ? "hidden" : false}
                animate="visible"
                transition={{ ...transition(TRANSITION.base), delay: enterCards ? delay(index) : 0 }}
              >
              <Link to={`/assessments/${assessment.id}`}>
                <Card interactive className="h-full">
                  <CardContent className="space-y-3 p-5">
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <p className="font-mono text-[11px] text-muted-foreground">{assessment.reference}</p>
                        <p className="line-clamp-2 font-semibold leading-tight">{assessment.name}</p>
                      </div>
                      <StatusBadge status={assessment.status} />
                    </div>

                    {assessment.client_name && (
                      <p className="truncate text-sm text-muted-foreground">{assessment.client_name}</p>
                    )}

                    {severities && (
                      <div className="flex flex-wrap gap-1.5">
                        {(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"] as const).map((sev) =>
                          severities[sev] > 0 ? (
                            <span
                              key={sev}
                              className="inline-flex items-center gap-1 rounded-md bg-muted px-1.5 py-0.5 text-[11px] font-medium"
                            >
                              <span className={cn("sev-dot", SEVERITY_DOT[sev])} />
                              {severities[sev]}
                            </span>
                          ) : null
                        )}
                        {stats?.findings_total === 0 && (
                          <span className="text-[11px] text-muted-foreground">No findings yet</span>
                        )}
                      </div>
                    )}

                    {stats && stats.findings_total > 0 && (
                      <div className="space-y-1">
                        <div className="flex items-center justify-between text-[11px] text-muted-foreground">
                          <span>Remediation</span>
                          <span>{stats.remediation_progress.toFixed(0)}%</span>
                        </div>
                        <Progress value={stats.remediation_progress} className="h-1.5" indicatorClassName="bg-success" />
                      </div>
                    )}

                    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 border-t pt-2.5 text-[11px] text-muted-foreground">
                      <span className="inline-flex items-center gap-1">
                        <Users className="h-3 w-3" /> {assessment.members?.length ?? 0}
                      </span>
                      <span>{stats?.targets ?? 0} targets</span>
                      <span>{stats?.scans ?? 0} scans</span>
                      {assessment.end_date && (
                        <span className="inline-flex items-center gap-1">
                          <CalendarDays className="h-3 w-3" /> {formatDate(assessment.end_date)}
                        </span>
                      )}
                      {stats && stats.overdue > 0 && (
                        <Badge variant="destructive" className="text-[10px]">{stats.overdue} overdue</Badge>
                      )}
                      {assessment.is_demo && <DemoBadge />}
                    </div>
                  </CardContent>
                </Card>
              </Link>
              </motion.div>
            )
          })}
        </div>
      )}

      <NewAssessmentDialog open={newOpen} onOpenChange={setNewOpen} />
    </>
  )
}
