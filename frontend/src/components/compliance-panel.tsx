import * as React from "react"
import { Link } from "react-router-dom"
import { ClipboardCheck, Info, ShieldCheck } from "lucide-react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge, SeverityBadge } from "@/components/ui/badge"
import { EmptyState, Progress, Separator, Tooltip } from "@/components/ui/misc"
import { cn } from "@/lib/utils"
import type { ComplianceFramework, ComplianceResponse } from "@/types"

/** Readiness is a health measure, so it reads green-to-red, not by severity. */
function readinessTone(value: number): { bar: string; text: string } {
  if (value >= 85) return { bar: "bg-success", text: "text-success" }
  if (value >= 60) return { bar: "bg-severity-medium", text: "text-severity-medium" }
  if (value >= 30) return { bar: "bg-severity-high", text: "text-severity-high" }
  return { bar: "bg-severity-critical", text: "text-severity-critical" }
}

function FrameworkBlock({ framework, assessmentId }: {
  framework: ComplianceFramework
  assessmentId: number
}) {
  const [expanded, setExpanded] = React.useState(false)
  const readiness = framework.readiness ?? 0
  const tone = readinessTone(readiness)
  const shown = expanded ? framework.controls : framework.controls.slice(0, 5)

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-end justify-between gap-2">
        <div>
          <p className="text-sm font-medium">{framework.label}</p>
          <p className="text-[11px] text-muted-foreground">
            {framework.controls_at_risk} of {framework.controls_affected} touched controls have open findings
          </p>
        </div>
        {framework.readiness == null ? (
          <Badge variant="muted">Not scored</Badge>
        ) : (
          <span className={cn("text-2xl font-bold tabular-nums", tone.text)}>
            {readiness.toFixed(0)}%
          </span>
        )}
      </div>

      <Progress value={readiness} indicatorClassName={tone.bar} />

      {framework.controls.length === 0 ? (
        <p className="text-xs text-muted-foreground">No findings map to this framework yet.</p>
      ) : (
        <>
          <ul className="space-y-1.5">
            {shown.map((control) => {
              const controlTone = readinessTone(control.readiness)
              return (
                <li key={control.id} className="flex items-center gap-3 rounded-md border px-2.5 py-1.5">
                  <code className="w-16 shrink-0 font-mono text-[11px] text-muted-foreground">
                    {control.id}
                  </code>
                  <span className="min-w-0 flex-1 truncate text-xs">{control.title}</span>
                  {control.open_findings > 0 && (
                    <Link
                      to={`/findings?assessment_id=${assessmentId}`}
                      className="shrink-0 text-[11px] text-muted-foreground hover:text-primary"
                    >
                      {control.open_findings} open
                    </Link>
                  )}
                  {control.worst_open_severity && (
                    <SeverityBadge
                      severity={control.worst_open_severity}
                      showDot={false}
                      className="shrink-0 px-1 py-0 text-[9px]"
                    />
                  )}
                  <span className={cn("w-11 shrink-0 text-right text-xs font-semibold tabular-nums", controlTone.text)}>
                    {control.readiness.toFixed(0)}%
                  </span>
                </li>
              )
            })}
          </ul>
          {framework.controls.length > 5 && (
            <button
              onClick={() => setExpanded((v) => !v)}
              className="text-xs font-medium text-primary hover:underline"
            >
              {expanded ? "Show fewer" : `Show all ${framework.controls.length} controls`}
            </button>
          )}
        </>
      )}
    </div>
  )
}

export function CompliancePanel({ data }: { data: ComplianceResponse }) {
  if (data.coverage.findings_considered === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ClipboardCheck className="h-4 w-4" /> Compliance readiness
          </CardTitle>
          <CardDescription>NIST SP 800-53 and ISO/IEC 27001 control coverage</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <EmptyState
            icon={ShieldCheck}
            title="Nothing to map yet"
            description="Control readiness is derived from findings — run a scan or raise a finding first."
          />
        </CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div className="space-y-1">
            <CardTitle className="flex items-center gap-2">
              <ClipboardCheck className="h-4 w-4" /> Compliance readiness
            </CardTitle>
            <CardDescription>
              Derived from {data.coverage.findings_mapped} of {data.coverage.findings_considered} findings
            </CardDescription>
          </div>
          <Tooltip
            label={`${data.coverage.catalogue_size} CWEs are mapped. ${data.coverage.findings_unmapped} finding(s) carry a CWE outside the table or none at all.`}
          >
            <Badge variant="muted" className="cursor-help">
              {data.coverage.mapping_rate.toFixed(0)}% mapped
            </Badge>
          </Tooltip>
        </div>
      </CardHeader>

      <CardContent className="space-y-5">
        {data.frameworks.map((framework, index) => (
          <React.Fragment key={framework.key}>
            {index > 0 && <Separator />}
            <FrameworkBlock framework={framework} assessmentId={data.assessment_id} />
          </React.Fragment>
        ))}

        {data.owasp_top_10.length > 0 && (
          <>
            <Separator />
            <div className="space-y-2">
              <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                OWASP Top 10 (2021)
              </p>
              <div className="flex flex-wrap gap-1.5">
                {data.owasp_top_10.map((category) => (
                  <Tooltip
                    key={category.id}
                    label={`${category.open_findings} open, ${category.resolved_findings} resolved`}
                  >
                    <span
                      className={cn(
                        "inline-flex cursor-help items-center gap-1.5 rounded-md px-2 py-1 text-[11px] font-medium ring-1 ring-inset",
                        category.open_findings > 0
                          ? "bg-severity-high/10 text-severity-high ring-severity-high/25"
                          : "bg-success/10 text-success ring-success/25"
                      )}
                    >
                      <span className="font-mono">{category.id}</span>
                      <span className="max-w-[11rem] truncate">{category.title}</span>
                      {category.open_findings > 0 && <span>· {category.open_findings}</span>}
                    </span>
                  </Tooltip>
                ))}
              </div>
            </div>
          </>
        )}

        <p className="flex items-start gap-1.5 rounded-md bg-muted/50 p-2.5 text-[11px] leading-relaxed text-muted-foreground">
          <Info className="mt-px h-3.5 w-3.5 shrink-0" />
          {data.disclaimer}
        </p>
      </CardContent>
    </Card>
  )
}
