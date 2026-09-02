/**
 * The application's motion vocabulary.
 *
 * Every duration, easing and variant lives here so the whole product moves the
 * same way. This is a security tool: motion exists to direct attention and to
 * make state changes legible, never to entertain. Two rules follow from that
 * and are enforced by the values below.
 *
 *   1. Nothing overshoots. No spring bounce, no elastic easing — a finding
 *      table that springs into place reads as a toy.
 *   2. Nothing outlasts a glance. The longest transition here is 360ms; past
 *      roughly that, motion stops feeling responsive and starts feeling slow
 *      to someone working through a list of vulnerabilities all day.
 */
import * as React from "react"
import { useReducedMotion } from "motion/react"
import type { Transition, Variants } from "motion/react"

/* ------------------------------------------------------------------ timing */

export const DURATION = {
  /** Hover, press, colour shifts — must feel instant. */
  instant: 0.12,
  /** Badges, small reveals. */
  fast: 0.18,
  /** The default: page transitions, dialogs, list rows. */
  base: 0.24,
  /** Deliberate reveals — the posture ring, attack-path graph. */
  slow: 0.36,
} as const

/**
 * A single decelerating curve for everything that enters, and a symmetrical
 * one for everything that leaves. Both are pure ease-out/ease-in: no negative
 * control points, so nothing can overshoot its final value.
 */
export const EASE = {
  out: [0.22, 0.61, 0.36, 1],
  in: [0.4, 0, 1, 1],
  inOut: [0.4, 0, 0.2, 1],
} as const

/* -------------------------------------------------------------- transitions */

export const TRANSITION = {
  fast: { duration: DURATION.fast, ease: EASE.out },
  base: { duration: DURATION.base, ease: EASE.out },
  slow: { duration: DURATION.slow, ease: EASE.out },
  exit: { duration: DURATION.fast, ease: EASE.in },
} satisfies Record<string, Transition>

/**
 * Counters settle rather than bounce. Damping is high relative to stiffness on
 * purpose: a critical-findings count that wobbles past its value and back
 * undermines the number it is reporting.
 */
export const COUNTER_SPRING = { stiffness: 90, damping: 20, mass: 0.6, restDelta: 0.5 } as const

/* ------------------------------------------------------------------ stagger */

/** Per-row delay, and the ceiling on total stagger time. */
export const STAGGER_STEP = 0.025
export const STAGGER_MAX_TOTAL = 0.4

/**
 * Delay for row `index`, capped so a long table finishes appearing quickly.
 * A hundred rows at 25ms each would take two and a half seconds; past the cap
 * every remaining row simply shares the final delay.
 */
export function staggerDelay(index: number): number {
  return Math.min(index * STAGGER_STEP, STAGGER_MAX_TOTAL)
}

/* ----------------------------------------------------------------- variants */

export const fadeUp: Variants = {
  hidden: { opacity: 0, y: 8 },
  visible: { opacity: 1, y: 0 },
}

export const fade: Variants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1 },
}

/**
 * Dialogs: a small scale so they read as arriving, not as zooming.
 *
 * The panel is centred with a -50%/-50% transform, and Motion writes `transform`
 * inline — so the centring has to be part of the animation rather than a utility
 * class, or the panel jumps to the corner the moment it animates.
 */
export const dialogVariants: Variants = {
  hidden: { opacity: 0, scale: 0.97, x: "-50%", y: "-48%" },
  visible: { opacity: 1, scale: 1, x: "-50%", y: "-50%" },
}

/** Reduced motion drops the movement, but the centring transform has to stay. */
export const dialogVariantsReduced: Variants = {
  hidden: { opacity: 0, scale: 1, x: "-50%", y: "-50%" },
  visible: { opacity: 1, scale: 1, x: "-50%", y: "-50%" },
}

export const toastVariants: Variants = {
  hidden: { opacity: 0, x: 16, scale: 0.98 },
  visible: { opacity: 1, x: 0, scale: 1 },
}

/* -------------------------------------------------------------------- hover */

/**
 * The single hover treatment for every interactive card. Applied through one
 * class so the lift is identical everywhere rather than drifting per component.
 */
export const CARD_HOVER =
  "transition-[transform,box-shadow,border-color] duration-150 ease-out " +
  "hover:-translate-y-0.5 hover:shadow-md hover:border-primary/30 " +
  "motion-reduce:transition-none motion-reduce:hover:translate-y-0"

/* --------------------------------------------------------------------- hook */

/**
 * One place that answers "should this move?".
 *
 * Returns the user's preference plus pre-neutralised values, so a component
 * never has to write its own reduced-motion branch. When motion is reduced,
 * transitions collapse to zero duration and offsets to zero — content still
 * appears, it simply arrives without travelling.
 */
export function useMotionPrefs() {
  const reduced = useReducedMotion() ?? false

  return {
    reduced,
    /** Transition to spend, already neutralised when motion is reduced. */
    transition: (t: Transition = TRANSITION.base): Transition =>
      reduced ? { duration: 0 } : t,
    /** Stagger delay, zero when motion is reduced. */
    delay: (index: number): number => (reduced ? 0 : staggerDelay(index)),
    /** Variants that translate become pure fades when motion is reduced. */
    variants: (v: Variants): Variants => (reduced ? fade : v),
  }
}

/**
 * True only for the first render in which `ready` becomes true.
 *
 * List rows are keyed by id, so a refetch that returns the same rows would
 * otherwise replay the entrance stagger on every poll — the findings table
 * re-cascading every thirty seconds while someone is reading it. This latches
 * after the first populated render so the stagger is genuinely an entrance.
 */
export function useEnterOnce(ready: boolean): boolean {
  const played = React.useRef(false)
  const shouldPlay = ready && !played.current
  React.useEffect(() => {
    if (ready) played.current = true
  }, [ready])
  return shouldPlay
}

/**
 * Ambient pulse for CRITICAL severity only, defined as keyframes in index.css.
 *
 * Intentionally slower than the ~300-400ms interaction budget: an ambient loop
 * that fast reads as an alarm. It is opt-in at the call site so it marks a single
 * prominent finding rather than strobing down a dense table.
 */
export const CRITICAL_PULSE = "critical-pulse"

/**
 * Per-column delay for the attack-path graph entrance.
 *
 * The graph is laid out left-to-right as prerequisite -> enabler -> outcome, so
 * revealing it column by column replays the causal direction of the chain. Three
 * columns at this step still finish inside the interaction budget.
 */
export const GRAPH_COLUMN_STEP = 0.09

/**
 * Entrance timing for one attack-path graph column, as CSS custom properties.
 *
 * ReactFlow mounts custom nodes through its own renderer, outside the path
 * Motion hooks into, so a `motion.div` there never animates. The keyframes live
 * in index.css instead — but the numbers still come from here, so there is one
 * place to change how the graph enters.
 */
export function graphEnterVars(depth: number): React.CSSProperties {
  return {
    "--enter-delay": `${depth * GRAPH_COLUMN_STEP}s`,
    "--enter-duration": `${DURATION.base}s`,
  } as React.CSSProperties
}
