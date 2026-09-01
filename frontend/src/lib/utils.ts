import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function formatDate(value?: string | null, withTime = false): string {
  if (!value) return "—"
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return "—"
  return d.toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    ...(withTime ? { hour: "2-digit", minute: "2-digit" } : {}),
  })
}

export function relativeTime(value?: string | null): string {
  if (!value) return "—"
  const then = new Date(value).getTime()
  if (Number.isNaN(then)) return "—"
  const diff = then - Date.now()
  const abs = Math.abs(diff)
  const units: [Intl.RelativeTimeFormatUnit, number][] = [
    ["year", 31536e6], ["month", 2592e6], ["day", 864e5],
    ["hour", 36e5], ["minute", 6e4], ["second", 1000],
  ]
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" })
  for (const [unit, ms] of units) {
    if (abs >= ms || unit === "second") return rtf.format(Math.round(diff / ms), unit)
  }
  return "—"
}

export function titleCase(value?: string | null): string {
  if (!value) return "—"
  return value
    .replace(/_/g, " ")
    .toLowerCase()
    .replace(/\b\w/g, (c) => c.toUpperCase())
}

export function initials(name?: string | null): string {
  if (!name) return "?"
  return name.trim().split(/\s+/).slice(0, 2).map((p) => p[0]?.toUpperCase() ?? "").join("")
}

export function formatBytes(bytes?: number | null): string {
  if (!bytes) return "0 B"
  const units = ["B", "KB", "MB", "GB"]
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1)
  return `${(bytes / 1024 ** i).toFixed(i === 0 ? 0 : 1)} ${units[i]}`
}
