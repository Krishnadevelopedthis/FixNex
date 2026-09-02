import * as React from "react"
import { AlertTriangle, RotateCcw } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"

interface State {
  error: Error | null
  info: React.ErrorInfo | null
}

/**
 * Catches render errors so one broken screen cannot blank the whole app.
 *
 * Without this, a single bad render unmounts the entire tree and the user is
 * left staring at an empty page with no way back.
 */
export class ErrorBoundary extends React.Component<{ children: React.ReactNode }, State> {
  state: State = { error: null, info: null }

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { error }
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    this.setState({ info })
    // Keep the detail in the console for developers as well as on screen.
    console.error("Render error:", error, info.componentStack)
  }

  render() {
    if (!this.state.error) return this.props.children

    return (
      <div className="flex min-h-[60vh] items-center justify-center p-6">
        <Card className="w-full max-w-2xl border-destructive/30">
          <CardContent className="space-y-4 p-6">
            <div className="flex items-start gap-3">
              <div className="rounded-full bg-destructive/10 p-2.5">
                <AlertTriangle className="h-5 w-5 text-destructive" />
              </div>
              <div className="space-y-1">
                <p className="font-semibold">This screen failed to render</p>
                <p className="text-sm text-muted-foreground">
                  The rest of the application is still working — you can go back or reload.
                </p>
              </div>
            </div>

            <pre className="max-h-48 overflow-auto rounded-md border bg-muted/50 p-3 font-mono text-[11px] leading-relaxed">
              {this.state.error.message}
              {this.state.info?.componentStack}
            </pre>

            <div className="flex gap-2">
              <Button onClick={() => this.setState({ error: null, info: null })}>
                <RotateCcw /> Try again
              </Button>
              <Button variant="outline" onClick={() => window.history.back()}>Go back</Button>
              <Button variant="ghost" onClick={() => window.location.reload()}>Reload</Button>
            </div>
          </CardContent>
        </Card>
      </div>
    )
  }
}
