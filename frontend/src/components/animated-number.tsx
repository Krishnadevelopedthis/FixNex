import * as React from "react"
import { useMotionValue, useMotionValueEvent, useSpring } from "motion/react"
import { COUNTER_SPRING, useMotionPrefs } from "@/lib/motion"

interface Props {
  value: number
  /** Decimal places to render; counts settle on integers, scores on one. */
  decimals?: number
  suffix?: string
  className?: string
}

/**
 * A number that settles into place rather than snapping.
 *
 * Driven by a motion value and spring rather than a timer: the spring owns the
 * easing, and re-targeting mid-flight (a refetch changing the number) is
 * continuous instead of restarting a fresh interval from zero.
 *
 * The spring is heavily damped on purpose — a critical-findings count that
 * overshoots and settles back would misreport, however briefly.
 */
export function AnimatedNumber({ value, decimals = 0, suffix = "", className }: Props) {
  const { reduced } = useMotionPrefs()
  const target = useMotionValue(0)
  const spring = useSpring(target, COUNTER_SPRING)
  const [shown, setShown] = React.useState(reduced ? value : 0)

  React.useEffect(() => {
    if (reduced) {
      setShown(value)
      return
    }
    target.set(value)
  }, [value, reduced, target])

  useMotionValueEvent(spring, "change", (latest) => {
    if (!reduced) setShown(latest)
  })

  const text = shown.toFixed(decimals)
  return (
    <span className={className} aria-label={`${value}${suffix}`}>
      {text}
      {suffix}
    </span>
  )
}
