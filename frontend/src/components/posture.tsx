import { Gauge, Info } from "lucide-react"
import { motion } from "motion/react"
import { AnimatedNumber } from "@/components/animated-number"
import { TRANSITION, useMotionPrefs } from "@/lib/motion"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { EmptyState, Progress, Separator, Tooltip } from "@/components/ui/misc"
import { SEVERITY_VAR } from "@/lib/severity"
import { cn } from "@/lib/utils"
import type { AssetHeatmap, PostureScore } from "@/types"

/** Posture is a health measure: high is good, so it reads green-to-red. */
function gradeTone(grade: string): { ring: string; text: string } {
  switch (grade) {
    case "A": return { ring: "hsl(var(--success))", text: "text-success" }
    case "B": return { ring: SEVERITY_VAR.LOW, text: "text-severity-low" }
    case "C": return { ring: SEVERITY_VAR.MEDIUM, text: "text-severity-medium" }
    case "D": return { ring: SEVERITY_VAR.HIGH, text: "text-severity-high" }
    default:  return { ring: SEVERITY_VAR.CRITICAL, text: "text-severity-critical" }
  }
}

export function PostureCard({ data }: { data: PostureScore }) {
  const tone = gradeTone(data.grade)
  const pct = Math.min(100, Math.max(0, data.score))
  const { reduced, transition } = useMotionPrefs()

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Gauge className="h-4 w-4" /> Security posture
        </CardTitle>
        <CardDescription>{data.summary}</CardDescription>
      </CardHeader>

      <CardContent className="space-y-4">
        <div className="flex items-center gap-5">
          <div className="relative h-24 w-24 shrink-0">
            <svg viewBox="0 0 36 36" className="h-full w-full -rotate-90">
              <circle cx="18" cy="18" r="15.5" fill="none" stroke="hsl(var(--muted))" strokeWidth="3.5" />
              <motion.circle
                cx="18" cy="18" r="15.5" fill="none" stroke={tone.ring} strokeWidth="3.5"
                strokeLinecap="round"
                initial={reduced ? false : { pathLength: 0 }}
                animate={{ pathLength: pct / 100 }}
                transition={transition(TRANSITION.slow)}
              />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-2xl font-bold leading-none tabular-nums">
                <AnimatedNumber value={data.score} />
              </span>
              <span className={cn("text-[11px] font-semibold", tone.text)}>Grade {data.grade}</span>
            </div>
          </div>

          <div className="grid flex-1 grid-cols-2 gap-2 text-sm">
            {[
              { label: "Total findings", value: data.totals.findings },
              { label: "Still open", value: data.totals.open },
              { label: "Closed", value: data.totals.closed },
              { label: "Resolution rate", value: `${data.totals.resolution_rate.toFixed(0)}%` },
            ].map((item) => (
              <div key={item.label} className="rounded-md bg-muted/50 px-2.5 py-1.5">
                <p className="text-[10px] uppercase tracking-wider text-muted-foreground">{item.label}</p>
                <p className="text-sm font-semibold">{item.value}</p>
              </div>
            ))}
          </div>
        </div>

        <Separator />

        <div className="space-y-2">
          <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
            What moved the score
          </p>
          {data.factors.map((factor) => (
            <div key={factor.key} className="space-y-1">
              <div className="flex items-baseline justify-between gap-2 text-xs">
                <Tooltip label={factor.explanation}>
                  <span className="cursor-help">{factor.label}</span>
                </Tooltip>
                <span className="shrink-0 tabular-nums text-muted-foreground">
                  {factor.count} ·{" "}
                  <span className={factor.penalty > 0 ? "font-semibold text-severity-high" : ""}>
                    {factor.penalty > 0 ? `−${factor.penalty.toFixed(1)}` : "0"}
                  </span>
                  <span className="text-muted-foreground/60"> / {factor.max_penalty}</span>
                </span>
              </div>
              <Progress
                value={(factor.penalty / factor.max_penalty) * 100}
                className="h-1"
                indicatorClassName={factor.penalty > 0 ? "bg-severity-high" : "bg-muted"}
              />
            </div>
          ))}
        </div>

        <p className="flex items-start gap-1.5 rounded-md bg-muted/50 p-2.5 text-[11px] leading-relaxed text-muted-foreground">
          <Info className="mt-px h-3.5 w-3.5 shrink-0" />
          {data.methodology}
        </p>
      </CardContent>
    </Card>
  )
}

export function AssetHeatmapCard({ data }: { data: AssetHeatmap }) {
  if (!data.assets.length) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Assets by severity</CardTitle>
          <CardDescription>Open findings per system</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <EmptyState title="No open findings" description="Nothing outstanding across any asset." />
        </CardContent>
      </Card>
    )
  }

  const intensity = (count: number) =>
    count === 0 ? 0.05 : 0.2 + 0.65 * (count / Math.max(data.max_count, 1))

  return (
    <Card>
      <CardHeader>
        <CardTitle>Assets by severity</CardTitle>
        <CardDescription>
          Open findings per system — the row is what a team actually owns
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr>
                <th className="pb-2 text-left text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                  Asset
                </th>
                {data.severities.map((severity) => (
                  <th
                    key={severity}
                    className="pb-2 text-center text-[10px] font-semibold uppercase tracking-wider text-muted-foreground"
                  >
                    {severity === "INFORMATIONAL" ? "Info" : severity.slice(0, 4)}
                  </th>
                ))}
                <th className="pb-2 pl-2 text-right text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                  Total
                </th>
              </tr>
            </thead>
            <tbody>
              {data.assets.map((asset) => (
                <tr key={asset.key}>
                  <td className="max-w-[13rem] py-1 pr-2">
                    <p className="truncate text-xs font-medium">{asset.name}</p>
                    <p className="text-[10px] text-muted-foreground">
                      {asset.criticality ? `${asset.criticality.toLowerCase()} criticality` : "unclassified"}
                      {asset.targets > 1 && ` · ${asset.targets} targets`}
                    </p>
                  </td>
                  {data.severities.map((severity) => {
                    const count = asset.counts[severity] ?? 0
                    return (
                      <td key={severity} className="p-0.5">
                        <div
                          className="relative flex h-9 items-center justify-center rounded"
                          title={`${asset.name}: ${count} open ${severity.toLowerCase()}`}
                        >
                          <span
                            className="absolute inset-0 rounded"
                            style={{ background: SEVERITY_VAR[severity], opacity: intensity(count) }}
                          />
                          <span className={cn("relative text-xs font-semibold", count === 0 && "text-muted-foreground/50")}>
                            {count}
                          </span>
                        </div>
                      </td>
                    )
                  })}
                  <td className="pl-2 text-right text-xs font-semibold tabular-nums">{asset.total}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  )
}
