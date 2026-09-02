import * as React from "react"
import { useMutation } from "@tanstack/react-query"
import { Bot, RefreshCw, Sparkles, TriangleAlert } from "lucide-react"
import { findingApi } from "@/services/endpoints"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Progress, Separator, Tooltip } from "@/components/ui/misc"
import { errorMessage } from "@/components/ui/toast"
import { cn, relativeTime } from "@/lib/utils"
import type { AITriageSuggestion, FindingDetail } from "@/types"

/** Reads as a likelihood, not a verdict — the wording matters here. */
function confidenceLabel(value: number): { text: string; tone: string } {
  if (value >= 0.75) return { text: "Likely a false positive", tone: "text-muted-foreground" }
  if (value >= 0.5) return { text: "Leans false positive", tone: "text-severity-medium" }
  if (value >= 0.25) return { text: "Leans genuine", tone: "text-severity-high" }
  return { text: "Likely genuine", tone: "text-severity-critical" }
}

export function AITriagePanel({ finding }: { finding: FindingDetail }) {
  const [suggestion, setSuggestion] = React.useState<AITriageSuggestion | null>(null)
  const [error, setError] = React.useState<string | null>(null)

  const mutation = useMutation({
    mutationFn: (refresh: boolean) => findingApi.aiTriage(finding.id, refresh),
    onSuccess: (data) => { setSuggestion(data); setError(null) },
    onError: (e) => { setError(errorMessage(e)); setSuggestion(null) },
  })

  const label = suggestion ? confidenceLabel(suggestion.false_positive_confidence) : null

  return (
    <div className="rounded-lg border border-dashed p-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="space-y-0.5">
          <p className="flex items-center gap-1.5 text-sm font-medium">
            <Sparkles className="h-4 w-4 text-primary" />
            AI suggestion
            <Badge variant="outline" className="ml-1 text-[10px] uppercase tracking-wider">
              not a verdict
            </Badge>
          </p>
          <p className="text-xs text-muted-foreground">
            A second opinion on whether this is a false positive, and how to fix it.
            Your verification decision is unchanged by it.
          </p>
        </div>
        <Button
          size="sm"
          variant={suggestion ? "outline" : "default"}
          loading={mutation.isPending}
          onClick={() => mutation.mutate(!!suggestion)}
        >
          {suggestion ? <><RefreshCw /> Regenerate</> : <><Bot /> Get suggestion</>}
        </Button>
      </div>

      {error && (
        <div className="mt-3 flex items-start gap-2 rounded-md border border-severity-medium/30 bg-severity-medium/10 p-2.5 text-xs">
          <TriangleAlert className="mt-px h-3.5 w-3.5 shrink-0 text-severity-medium" />
          <span className="text-muted-foreground">{error}</span>
        </div>
      )}

      {suggestion && (
        <div className="mt-4 space-y-4">
          <div className="space-y-1.5">
            <div className="flex items-baseline justify-between gap-2">
              <span className="text-xs text-muted-foreground">False-positive likelihood</span>
              <span className={cn("text-sm font-semibold", label?.tone)}>
                {(suggestion.false_positive_confidence * 100).toFixed(0)}% · {label?.text}
              </span>
            </div>
            <Progress
              value={suggestion.false_positive_confidence * 100}
              className="h-1.5"
              indicatorClassName="bg-muted-foreground"
            />
          </div>

          <div className="space-y-1">
            <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
              Reasoning
            </p>
            <p className="whitespace-pre-wrap text-sm leading-relaxed">{suggestion.reasoning}</p>
          </div>

          {suggestion.suggested_fix && (
            <div className="space-y-1">
              <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                Suggested fix
              </p>
              <pre className="max-h-56 overflow-auto whitespace-pre-wrap rounded-md border bg-muted/50 p-3 font-mono text-[11px] leading-relaxed">
                {suggestion.suggested_fix}
              </pre>
            </div>
          )}

          {suggestion.verification_steps && (
            <div className="space-y-1">
              <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                How to verify it yourself
              </p>
              <p className="whitespace-pre-wrap text-sm leading-relaxed">
                {suggestion.verification_steps}
              </p>
            </div>
          )}

          <Separator />

          <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] text-muted-foreground">
            <span>{suggestion.disclaimer}</span>
            <Tooltip
              label={
                suggestion.input_tokens
                  ? `${suggestion.input_tokens} in / ${suggestion.output_tokens} out tokens`
                  : undefined
              }
            >
              <span className="shrink-0 cursor-help">
                {suggestion.model}
                {suggestion.effort ? ` · ${suggestion.effort} effort` : ""}
                {suggestion.cached && suggestion.generated_at
                  ? ` · cached ${relativeTime(suggestion.generated_at)}`
                  : ""}
              </span>
            </Tooltip>
          </div>
        </div>
      )}
    </div>
  )
}
