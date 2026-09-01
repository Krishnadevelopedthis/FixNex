import * as React from "react"
import { useMutation } from "@tanstack/react-query"
import { ArrowUpRight, Highlighter, Square, Trash2, Type } from "lucide-react"
import { evidenceApi } from "@/services/endpoints"
import { api } from "@/services/api"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { errorMessage, useToast } from "@/components/ui/toast"
import { cn } from "@/lib/utils"
import type { Annotation, Evidence } from "@/types"

type Tool = Annotation["kind"]

const TOOLS: { kind: Tool; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
  { kind: "rect", label: "Rectangle", icon: Square },
  { kind: "arrow", label: "Arrow", icon: ArrowUpRight },
  { kind: "highlight", label: "Highlight", icon: Highlighter },
  { kind: "text", label: "Text", icon: Type },
]

const COLORS = ["#ef4444", "#f59e0b", "#3b82f6", "#22c55e"]

/**
 * Lightweight evidence annotation.
 *
 * Deliberately minimal — enough to point at the important part of a screenshot,
 * not a general-purpose image editor. Coordinates are stored as percentages so
 * annotations survive any rendered size.
 */
export function EvidenceAnnotator({ evidence, onSaved }: {
  evidence: Evidence
  onSaved: () => void
}) {
  const { toast } = useToast()
  const [imageUrl, setImageUrl] = React.useState<string | null>(null)
  const [tool, setTool] = React.useState<Tool>("rect")
  const [color, setColor] = React.useState(COLORS[0])
  const [annotations, setAnnotations] = React.useState<Annotation[]>(evidence.annotations ?? [])
  const [draft, setDraft] = React.useState<Annotation | null>(null)
  const [textValue, setTextValue] = React.useState("")
  const surfaceRef = React.useRef<HTMLDivElement>(null)

  // The image is fetched through the authenticated client, so it cannot be a plain src.
  React.useEffect(() => {
    let revoked: string | null = null
    api.get(`/evidence/${evidence.id}/download`, { responseType: "blob" })
      .then((response) => {
        revoked = URL.createObjectURL(response.data)
        setImageUrl(revoked)
      })
      .catch(() => setImageUrl(null))
    return () => { if (revoked) URL.revokeObjectURL(revoked) }
  }, [evidence.id])

  const saveMutation = useMutation({
    mutationFn: () => evidenceApi.annotate(evidence.id, annotations),
    onSuccess: () => { toast("success", "Annotations saved"); onSaved() },
    onError: (e) => toast("error", "Could not save annotations", errorMessage(e)),
  })

  function relativePoint(event: React.MouseEvent) {
    const rect = surfaceRef.current!.getBoundingClientRect()
    return {
      x: ((event.clientX - rect.left) / rect.width) * 100,
      y: ((event.clientY - rect.top) / rect.height) * 100,
    }
  }

  function handleMouseDown(event: React.MouseEvent) {
    const point = relativePoint(event)
    if (tool === "text") {
      if (!textValue.trim()) {
        toast("info", "Type the label first", "Enter the text to place, then click the image.")
        return
      }
      setAnnotations((prev) => [
        ...prev,
        { id: crypto.randomUUID(), kind: "text", x: point.x, y: point.y, text: textValue, color },
      ])
      setTextValue("")
      return
    }
    setDraft({ id: crypto.randomUUID(), kind: tool, x: point.x, y: point.y, width: 0, height: 0, x2: point.x, y2: point.y, color })
  }

  function handleMouseMove(event: React.MouseEvent) {
    if (!draft) return
    const point = relativePoint(event)
    setDraft({ ...draft, width: point.x - draft.x, height: point.y - draft.y, x2: point.x, y2: point.y })
  }

  function handleMouseUp() {
    if (!draft) return
    const meaningful = Math.abs(draft.width ?? 0) > 1 || Math.abs(draft.height ?? 0) > 1
    if (meaningful) setAnnotations((prev) => [...prev, draft])
    setDraft(null)
  }

  const shown = draft ? [...annotations, draft] : annotations

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex items-center gap-1 rounded-md border p-1">
          {TOOLS.map(({ kind, label, icon: Icon }) => (
            <button
              key={kind}
              onClick={() => setTool(kind)}
              title={label}
              className={cn(
                "rounded p-1.5 transition-colors",
                tool === kind ? "bg-primary text-primary-foreground" : "hover:bg-accent"
              )}
            >
              <Icon className="h-4 w-4" />
            </button>
          ))}
        </div>
        <div className="flex items-center gap-1 rounded-md border p-1">
          {COLORS.map((c) => (
            <button
              key={c}
              onClick={() => setColor(c)}
              className={cn("h-6 w-6 rounded", color === c && "ring-2 ring-offset-1 ring-offset-background ring-foreground")}
              style={{ background: c }}
            />
          ))}
        </div>
        {tool === "text" && (
          <Input
            value={textValue}
            onChange={(e) => setTextValue(e.target.value)}
            placeholder="Label text, then click the image"
            className="h-8 w-56"
          />
        )}
        <Button
          variant="ghost" size="sm"
          onClick={() => setAnnotations([])}
          disabled={annotations.length === 0}
        >
          <Trash2 /> Clear
        </Button>
        <div className="ml-auto">
          <Button size="sm" loading={saveMutation.isPending} onClick={() => saveMutation.mutate()}>
            Save annotations
          </Button>
        </div>
      </div>

      <div
        ref={surfaceRef}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={() => setDraft(null)}
        className="relative select-none overflow-hidden rounded-md border bg-muted"
        style={{ cursor: "crosshair", minHeight: 240 }}
      >
        {imageUrl ? (
          <img src={imageUrl} alt={evidence.filename} className="block w-full" draggable={false} />
        ) : (
          <div className="flex h-60 items-center justify-center text-sm text-muted-foreground">
            Loading image…
          </div>
        )}

        <svg className="pointer-events-none absolute inset-0 h-full w-full" viewBox="0 0 100 100" preserveAspectRatio="none">
          <defs>
            {COLORS.map((c) => (
              <marker key={c} id={`arrow-${c.slice(1)}`} markerWidth="4" markerHeight="4" refX="3" refY="2" orient="auto">
                <path d="M0,0 L4,2 L0,4 z" fill={c} />
              </marker>
            ))}
          </defs>
          {shown.map((a) => {
            if (a.kind === "rect") {
              const x = Math.min(a.x, a.x + (a.width ?? 0))
              const y = Math.min(a.y, a.y + (a.height ?? 0))
              return (
                <rect
                  key={a.id} x={x} y={y}
                  width={Math.abs(a.width ?? 0)} height={Math.abs(a.height ?? 0)}
                  fill="none" stroke={a.color} strokeWidth={0.5} vectorEffect="non-scaling-stroke"
                />
              )
            }
            if (a.kind === "highlight") {
              const x = Math.min(a.x, a.x + (a.width ?? 0))
              const y = Math.min(a.y, a.y + (a.height ?? 0))
              return (
                <rect
                  key={a.id} x={x} y={y}
                  width={Math.abs(a.width ?? 0)} height={Math.abs(a.height ?? 0)}
                  fill={a.color} opacity={0.28}
                />
              )
            }
            if (a.kind === "arrow") {
              return (
                <line
                  key={a.id} x1={a.x} y1={a.y} x2={a.x2} y2={a.y2}
                  stroke={a.color} strokeWidth={0.6} vectorEffect="non-scaling-stroke"
                  markerEnd={`url(#arrow-${(a.color ?? COLORS[0]).slice(1)})`}
                />
              )
            }
            return null
          })}
        </svg>

        {/* Text annotations are HTML so they stay legible regardless of aspect ratio. */}
        {shown.filter((a) => a.kind === "text").map((a) => (
          <span
            key={a.id}
            className="pointer-events-none absolute -translate-y-1/2 whitespace-nowrap rounded px-1.5 py-0.5 text-xs font-semibold shadow"
            style={{ left: `${a.x}%`, top: `${a.y}%`, background: a.color, color: "#fff" }}
          >
            {a.text}
          </span>
        ))}
      </div>

      <p className="text-xs text-muted-foreground">
        {annotations.length} annotation{annotations.length === 1 ? "" : "s"}. Drag to draw; annotations
        are stored with the evidence metadata and never modify the original file.
      </p>
    </div>
  )
}
