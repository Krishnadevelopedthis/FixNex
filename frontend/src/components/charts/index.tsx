import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Legend, Pie, PieChart,
  ResponsiveContainer, Tooltip as RTooltip, XAxis, YAxis,
} from "recharts"
import { SEVERITY_VAR } from "@/lib/severity"
import { cn, titleCase } from "@/lib/utils"

const AXIS = {
  stroke: "hsl(var(--muted-foreground))",
  fontSize: 11,
  tickLine: false,
  axisLine: false,
}

function ChartTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null
  return (
    <div className="rounded-md border bg-popover px-2.5 py-2 text-xs shadow-md">
      {label != null && <p className="mb-1 font-medium">{titleCase(String(label))}</p>}
      {payload.map((entry: any) => (
        <p key={entry.dataKey ?? entry.name} className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-full" style={{ background: entry.color ?? entry.fill }} />
          <span className="text-muted-foreground">{titleCase(entry.name)}:</span>
          <span className="font-medium">{entry.value}</span>
        </p>
      ))}
    </div>
  )
}

/** Horizontal severity distribution — the dashboard's primary breakdown. */
export function SeverityBarChart({ data, height = 200 }: {
  data: { key: string; count: number }[]
  height?: number
}) {
  if (!data.some((d) => d.count > 0)) {
    return <ChartEmpty height={height} message="No findings to chart yet" />
  }
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} layout="vertical" margin={{ left: 6, right: 16, top: 4, bottom: 4 }}>
        <CartesianGrid horizontal={false} stroke="hsl(var(--border))" strokeDasharray="3 3" />
        <XAxis type="number" allowDecimals={false} {...AXIS} />
        <YAxis
          type="category"
          dataKey="key"
          width={92}
          tickFormatter={(v) => (v === "INFORMATIONAL" ? "Info" : titleCase(v))}
          {...AXIS}
        />
        <RTooltip content={<ChartTooltip />} cursor={{ fill: "hsl(var(--muted))", opacity: 0.4 }} />
        <Bar dataKey="count" name="Findings" radius={[0, 4, 4, 0]} barSize={18}>
          {data.map((entry) => (
            <Cell key={entry.key} fill={SEVERITY_VAR[entry.key] ?? SEVERITY_VAR.INFORMATIONAL} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}

export function RiskDonutChart({ data, height = 210 }: {
  data: { key: string; count: number }[]
  height?: number
}) {
  const filtered = data.filter((d) => d.count > 0)
  if (!filtered.length) return <ChartEmpty height={height} message="No risk data yet" />
  const total = filtered.reduce((sum, d) => sum + d.count, 0)
  return (
    <div className="relative">
      <ResponsiveContainer width="100%" height={height}>
        <PieChart>
          <Pie
            data={filtered}
            dataKey="count"
            nameKey="key"
            innerRadius="58%"
            outerRadius="82%"
            paddingAngle={2}
            stroke="none"
          >
            {filtered.map((entry) => (
              <Cell key={entry.key} fill={SEVERITY_VAR[entry.key] ?? SEVERITY_VAR.INFORMATIONAL} />
            ))}
          </Pie>
          <RTooltip content={<ChartTooltip />} />
          <Legend
            verticalAlign="bottom"
            height={28}
            iconType="circle"
            iconSize={7}
            formatter={(value) => (
              <span className="text-xs text-muted-foreground">
                {value === "INFORMATIONAL" ? "Info" : titleCase(String(value))}
              </span>
            )}
          />
        </PieChart>
      </ResponsiveContainer>
      <div className="pointer-events-none absolute inset-x-0 top-[38%] -translate-y-1/2 text-center">
        <p className="text-2xl font-bold leading-none">{total}</p>
        <p className="text-[10px] uppercase tracking-wider text-muted-foreground">findings</p>
      </div>
    </div>
  )
}

export function CvssHistogram({ data, height = 180 }: {
  data: { key: string; count: number }[]
  height?: number
}) {
  if (!data.some((d) => d.count > 0)) return <ChartEmpty height={height} message="No CVSS data yet" />
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} margin={{ left: -18, right: 8, top: 4, bottom: 4 }}>
        <CartesianGrid vertical={false} stroke="hsl(var(--border))" strokeDasharray="3 3" />
        <XAxis dataKey="key" {...AXIS} />
        <YAxis allowDecimals={false} {...AXIS} />
        <RTooltip content={<ChartTooltip />} cursor={{ fill: "hsl(var(--muted))", opacity: 0.4 }} />
        <Bar dataKey="count" name="Findings" radius={[4, 4, 0, 0]} barSize={30}>
          {data.map((entry) => {
            const lower = parseFloat(entry.key)
            const band =
              lower >= 9 ? "CRITICAL" : lower >= 7 ? "HIGH" : lower >= 4 ? "MEDIUM" : lower > 0 ? "LOW" : "INFORMATIONAL"
            return <Cell key={entry.key} fill={SEVERITY_VAR[band]} />
          })}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}

export function TrendChart({ data, height = 200 }: {
  data: { date: string; discovered: number; closed: number }[]
  height?: number
}) {
  if (!data.length) return <ChartEmpty height={height} message="No activity yet" />
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ left: -18, right: 8, top: 4, bottom: 4 }}>
        <defs>
          <linearGradient id="gDiscovered" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={SEVERITY_VAR.HIGH} stopOpacity={0.35} />
            <stop offset="100%" stopColor={SEVERITY_VAR.HIGH} stopOpacity={0} />
          </linearGradient>
          <linearGradient id="gClosed" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="hsl(var(--success))" stopOpacity={0.35} />
            <stop offset="100%" stopColor="hsl(var(--success))" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid vertical={false} stroke="hsl(var(--border))" strokeDasharray="3 3" />
        <XAxis
          dataKey="date"
          tickFormatter={(v) => new Date(v).toLocaleDateString(undefined, { month: "short", day: "numeric" })}
          {...AXIS}
        />
        <YAxis allowDecimals={false} {...AXIS} />
        <RTooltip content={<ChartTooltip />} />
        <Area type="monotone" dataKey="discovered" name="Discovered" stroke={SEVERITY_VAR.HIGH} fill="url(#gDiscovered)" strokeWidth={2} />
        <Area type="monotone" dataKey="closed" name="Closed" stroke="hsl(var(--success))" fill="url(#gClosed)" strokeWidth={2} />
      </AreaChart>
    </ResponsiveContainer>
  )
}

const BANDS = ["LOW", "MEDIUM", "HIGH"] as const

/** Impact × likelihood heat map built from the contextual risk engine's output. */
export function RiskHeatmap({ data }: { data: { impact: string; likelihood: string; count: number }[] }) {
  const lookup = new Map(data.map((d) => [`${d.impact}|${d.likelihood}`, d.count]))
  const max = Math.max(1, ...data.map((d) => d.count))

  function cellTone(impact: string, likelihood: string, count: number) {
    const score = BANDS.indexOf(impact as any) + BANDS.indexOf(likelihood as any)
    const severity = score >= 3 ? "CRITICAL" : score === 2 ? "HIGH" : score === 1 ? "MEDIUM" : "LOW"
    const intensity = count === 0 ? 0.06 : 0.18 + 0.62 * (count / max)
    return { background: SEVERITY_VAR[severity], opacity: intensity }
  }

  return (
    <div className="space-y-2">
      <div className="flex gap-2">
        <div className="flex w-16 shrink-0 items-center justify-end pr-1">
          <span className="text-[10px] uppercase tracking-wider text-muted-foreground">Impact</span>
        </div>
        <div className="grid flex-1 grid-cols-3 gap-2">
          {[...BANDS].reverse().map((impact) => (
            <div key={impact} className="contents" />
          ))}
        </div>
      </div>
      {[...BANDS].reverse().map((impact) => (
        <div key={impact} className="flex items-center gap-2">
          <span className="w-16 shrink-0 pr-1 text-right text-[11px] font-medium capitalize text-muted-foreground">
            {impact.toLowerCase()}
          </span>
          <div className="grid flex-1 grid-cols-3 gap-2">
            {BANDS.map((likelihood) => {
              const count = lookup.get(`${impact}|${likelihood}`) ?? 0
              const tone = cellTone(impact, likelihood, count)
              return (
                <div
                  key={likelihood}
                  className="relative flex h-14 items-center justify-center rounded-md border"
                  title={`Impact ${titleCase(impact)} · Likelihood ${titleCase(likelihood)}: ${count} finding(s)`}
                >
                  <span className="absolute inset-0 rounded-md" style={tone} />
                  <span className={cn("relative text-sm font-semibold", count === 0 && "text-muted-foreground")}>
                    {count}
                  </span>
                </div>
              )
            })}
          </div>
        </div>
      ))}
      <div className="flex gap-2">
        <span className="w-16 shrink-0" />
        <div className="grid flex-1 grid-cols-3 gap-2">
          {BANDS.map((likelihood) => (
            <span key={likelihood} className="text-center text-[11px] font-medium capitalize text-muted-foreground">
              {likelihood.toLowerCase()}
            </span>
          ))}
        </div>
      </div>
      <p className="pt-1 text-center text-[10px] uppercase tracking-wider text-muted-foreground">
        Likelihood
      </p>
    </div>
  )
}

function ChartEmpty({ height, message }: { height: number; message: string }) {
  return (
    <div className="flex items-center justify-center text-xs text-muted-foreground" style={{ height }}>
      {message}
    </div>
  )
}
