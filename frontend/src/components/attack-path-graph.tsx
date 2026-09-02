import * as React from "react"
import { Link } from "react-router-dom"
import {
  Background, BackgroundVariant, Controls, Handle, MarkerType, Position,
  ReactFlow, type Edge, type Node, type NodeProps,
} from "@xyflow/react"
import "@xyflow/react/dist/style.css"
import { AlertTriangle, Bug, Info, ShieldAlert, Waypoints } from "lucide-react"
import { graphEnterVars } from "@/lib/motion"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge, SeverityBadge } from "@/components/ui/badge"
import { EmptyState, Separator, Tooltip } from "@/components/ui/misc"
import { SEVERITY_VAR } from "@/lib/severity"
import { titleCase } from "@/lib/utils"
import { useTheme } from "@/hooks/useTheme"
import type { AttackPathNode, AttackPathResponse } from "@/types"

/* ------------------------------------------------------------- custom nodes */

function FindingNode({ data }: NodeProps) {
  const node = data.node as AttackPathNode
  const role = data.role as string
  const depth = (data.depth as number) ?? 0
  return (
    <div
      className="graph-node-enter w-56 rounded-lg border bg-card p-2.5 shadow-sm"
      style={{
        ...graphEnterVars(depth),
        borderLeft: `3px solid ${SEVERITY_VAR[node.severity] ?? SEVERITY_VAR.INFORMATIONAL}`,
      }}
    >
      <Handle type="source" position={Position.Right} className="!h-2 !w-2 !border-0 !bg-muted-foreground" />
      <div className="mb-1 flex items-center justify-between gap-2">
        <Link
          to={`/findings/${node.finding_id}`}
          className="font-mono text-[10px] text-primary hover:underline"
        >
          {node.reference}
        </Link>
        <Badge variant="muted" className="px-1 py-0 text-[9px] uppercase">{role}</Badge>
      </div>
      <p className="mb-1.5 line-clamp-2 text-xs font-medium leading-snug">{node.title}</p>
      <div className="flex items-center gap-1.5">
        <SeverityBadge severity={node.severity} showDot={false} className="px-1 py-0 text-[9px]" />
        {node.cwe_id && <span className="text-[9px] text-muted-foreground">{node.cwe_id}</span>}
      </div>
    </div>
  )
}

function OutcomeNode({ data }: NodeProps) {
  const node = data.node as AttackPathNode
  const tone = SEVERITY_VAR[node.severity] ?? SEVERITY_VAR.HIGH
  const depth = (data.depth as number) ?? 0
  return (
    <Tooltip label={node.rationale}>
      <div
        className="graph-node-enter w-60 rounded-lg border-2 border-dashed p-2.5 shadow-sm"
        style={{
          ...graphEnterVars(depth),
          borderColor: tone,
          background: `color-mix(in srgb, ${tone} 10%, transparent)`,
        }}
      >
        <Handle type="target" position={Position.Left} className="!h-2 !w-2 !border-0 !bg-muted-foreground" />
        <div className="mb-1 flex items-center gap-1.5">
          <ShieldAlert className="h-3.5 w-3.5 shrink-0" style={{ color: tone }} />
          <span className="text-[9px] font-semibold uppercase tracking-wider" style={{ color: tone }}>
            Potential outcome
          </span>
        </div>
        <p className="line-clamp-3 text-xs font-medium leading-snug">{node.title}</p>
        <p className="mt-1 text-[9px] text-muted-foreground">{node.rule_name}</p>
      </div>
    </Tooltip>
  )
}

const NODE_TYPES = { findingNode: FindingNode, outcomeNode: OutcomeNode }

/* ------------------------------------------------------------------ layout */

/**
 * Lay the graph out in three columns: prerequisites, enablers, outcomes.
 *
 * The shape is always "two findings imply one outcome", so a deterministic
 * layered layout reads far better here than a force-directed one — and it
 * keeps the causal direction (left to right) obvious.
 */
function layout(data: AttackPathResponse): { nodes: Node[]; edges: Edge[] } {
  const roleOf = new Map<string, string>()
  for (const edge of data.edges) roleOf.set(edge.source, edge.role)

  const prerequisites = data.nodes.filter((n) => n.kind === "finding" && roleOf.get(n.id) === "prerequisite")
  const enablers = data.nodes.filter((n) => n.kind === "finding" && roleOf.get(n.id) === "enabler")
  const outcomes = data.nodes.filter((n) => n.kind === "outcome")

  const ROW = 108
  const column = (items: AttackPathNode[], x: number, type: string, depth: number) =>
    items.map((node, index) => ({
      id: node.id,
      type,
      position: { x, y: index * ROW },
      data: { node, role: roleOf.get(node.id) ?? "finding", depth },
      draggable: true,
    }))

  const nodes: Node[] = [
    ...column(prerequisites, 0, "findingNode", 0),
    ...column(enablers, 300, "findingNode", 1),
    ...column(outcomes, 620, "outcomeNode", 2),
  ]

  const edges: Edge[] = data.edges.map((edge) => ({
    id: edge.id,
    source: edge.source,
    target: edge.target,
    label: edge.label,
    animated: edge.role === "enabler",
    markerEnd: { type: MarkerType.ArrowClosed, width: 14, height: 14 },
    style: {
      stroke: edge.role === "enabler" ? SEVERITY_VAR.HIGH : "hsl(var(--muted-foreground))",
      strokeWidth: 1.5,
    },
    labelStyle: { fontSize: 10, fill: "hsl(var(--muted-foreground))" },
    labelBgStyle: { fill: "hsl(var(--card))" },
  }))

  return { nodes, edges }
}

/* ------------------------------------------------------------------- panel */

export function AttackPathPanel({ data }: { data: AttackPathResponse }) {
  const { theme } = useTheme()
  const { nodes, edges } = React.useMemo(() => layout(data), [data])

  if (data.summary.paths === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Waypoints className="h-4 w-4" /> Attack paths
          </CardTitle>
          <CardDescription>
            Chains where one finding makes another materially more dangerous.
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <EmptyState
            icon={Waypoints}
            title="No attack chains detected"
            description={
              data.summary.findings_considered === 0
                ? "There are no live findings in this assessment yet."
                : `None of the ${data.summary.findings_considered} live findings combine into a known chain across the ${data.summary.rules_evaluated} rules evaluated.`
            }
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
              <Waypoints className="h-4 w-4" /> Attack paths
            </CardTitle>
            <CardDescription>
              {data.summary.paths} chain{data.summary.paths === 1 ? "" : "s"} across{" "}
              {data.summary.findings_in_paths} findings
              {data.summary.escalating_paths > 0 && (
                <> · {data.summary.escalating_paths} outrank{data.summary.escalating_paths === 1 ? "s" : ""} their parts</>
              )}
            </CardDescription>
          </div>
          {data.summary.highest_outcome_severity && (
            <SeverityBadge severity={data.summary.highest_outcome_severity} />
          )}
        </div>
      </CardHeader>

      <CardContent className="space-y-4">
        <div className="attack-graph-enter h-[420px] overflow-hidden rounded-lg border bg-muted/20">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={NODE_TYPES}
            fitView
            fitViewOptions={{ padding: 0.15 }}
            minZoom={0.3}
            maxZoom={1.6}
            proOptions={{ hideAttribution: true }}
            colorMode={theme}
          >
            <Background variant={BackgroundVariant.Dots} gap={16} size={1} />
            <Controls showInteractive={false} />
          </ReactFlow>
        </div>

        <Separator />

        <div className="space-y-2">
          <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
            Chains
          </p>
          {data.paths.map((path, index) => (
            <div key={`${path.rule_id}-${index}`} className="rounded-md border p-3">
              <div className="mb-1.5 flex flex-wrap items-center gap-2">
                <SeverityBadge severity={path.outcome_severity} />
                <span className="text-sm font-medium">{path.outcome}</span>
                {path.escalates && (
                  <Tooltip label="The chain is more severe than either finding on its own.">
                    <Badge className="gap-1 text-[10px]">
                      <AlertTriangle className="h-2.5 w-2.5" /> Escalates
                    </Badge>
                  </Tooltip>
                )}
                {path.same_surface && (
                  <Badge variant="muted" className="text-[10px]">Same endpoint</Badge>
                )}
              </div>

              <div className="flex flex-wrap items-center gap-1.5 text-xs">
                {[path.prerequisite, path.enabler].map((step, i) => (
                  <React.Fragment key={step.finding_id}>
                    {i > 0 && <span className="text-muted-foreground">+</span>}
                    <Link
                      to={`/findings/${step.finding_id}`}
                      className="inline-flex items-center gap-1 rounded border px-1.5 py-0.5 hover:border-primary/40 hover:text-primary"
                    >
                      <Bug className="h-3 w-3 shrink-0" />
                      <span className="font-mono text-[10px]">{step.reference}</span>
                      <span className="max-w-[16rem] truncate">{step.title}</span>
                    </Link>
                  </React.Fragment>
                ))}
                <span className="text-muted-foreground">→</span>
                <span className="font-medium">{titleCase(path.outcome_severity)}</span>
              </div>

              <p className="mt-1.5 text-[11px] leading-relaxed text-muted-foreground">
                {path.rationale}
              </p>
            </div>
          ))}
        </div>

        <p className="flex items-start gap-1.5 rounded-md bg-muted/50 p-2.5 text-[11px] leading-relaxed text-muted-foreground">
          <Info className="mt-px h-3.5 w-3.5 shrink-0" />
          {data.disclaimer}
        </p>
      </CardContent>
    </Card>
  )
}
