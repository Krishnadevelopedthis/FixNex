import * as React from "react"
import { motion } from "motion/react"
import { cn } from "@/lib/utils"
import { TRANSITION, fadeUp, useMotionPrefs } from "@/lib/motion"

export const Table = ({ className, ...props }: React.HTMLAttributes<HTMLTableElement>) => (
  <div className="w-full overflow-x-auto">
    <table className={cn("w-full caption-bottom text-sm", className)} {...props} />
  </div>
)

export const THead = ({ className, ...props }: React.HTMLAttributes<HTMLTableSectionElement>) => (
  <thead className={cn("[&_tr]:border-b", className)} {...props} />
)

export const TBody = ({ className, ...props }: React.HTMLAttributes<HTMLTableSectionElement>) => (
  <tbody className={cn("[&_tr:last-child]:border-0", className)} {...props} />
)

export const TR = ({ className, ...props }: React.HTMLAttributes<HTMLTableRowElement>) => (
  <tr className={cn("border-b transition-colors hover:bg-muted/50 data-[state=selected]:bg-muted", className)} {...props} />
)

/**
 * A table row that can enter with a staggered delay.
 *
 * `enter` is passed by the list, not decided here: the row does not know
 * whether this is a first paint or the thirtieth poll of the same data.
 */
export function MotionTR({
  index, enter, className, children, ...props
}: React.HTMLAttributes<HTMLTableRowElement> & { index: number; enter: boolean }) {
  const { transition, variants, delay } = useMotionPrefs()
  return (
    <motion.tr
      variants={variants(fadeUp)}
      initial={enter ? "hidden" : false}
      animate="visible"
      transition={{ ...transition(TRANSITION.base), delay: enter ? delay(index) : 0 }}
      className={cn(
        "border-b transition-colors hover:bg-muted/50 data-[state=selected]:bg-muted",
        className
      )}
      {...(props as any)}
    >
      {children}
    </motion.tr>
  )
}

export const TH = ({ className, ...props }: React.ThHTMLAttributes<HTMLTableCellElement>) => (
  <th
    className={cn(
      "h-10 whitespace-nowrap px-3 text-left align-middle text-xs font-semibold uppercase tracking-wide text-muted-foreground",
      className
    )}
    {...props}
  />
)

export const TD = ({ className, ...props }: React.TdHTMLAttributes<HTMLTableCellElement>) => (
  <td className={cn("px-3 py-2.5 align-middle", className)} {...props} />
)

/** Sortable column header. */
export function SortableTH({ label, field, sort, onSort, className }: {
  label: string
  field: string
  sort: { by: string; order: "asc" | "desc" }
  onSort: (field: string) => void
  className?: string
}) {
  const active = sort.by === field
  return (
    <TH className={className}>
      <button
        onClick={() => onSort(field)}
        className={cn("inline-flex items-center gap-1 hover:text-foreground", active && "text-foreground")}
      >
        {label}
        <span className={cn("text-[10px] transition-opacity", active ? "opacity-100" : "opacity-30")}>
          {active && sort.order === "asc" ? "▲" : "▼"}
        </span>
      </button>
    </TH>
  )
}

export function Pagination({ page, pages, total, pageSize, onPage }: {
  page: number; pages: number; total: number; pageSize: number; onPage: (p: number) => void
}) {
  if (total === 0) return null
  const from = (page - 1) * pageSize + 1
  const to = Math.min(page * pageSize, total)
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 border-t px-4 py-3 text-sm">
      <p className="text-muted-foreground">
        Showing <span className="font-medium text-foreground">{from}</span>–
        <span className="font-medium text-foreground">{to}</span> of{" "}
        <span className="font-medium text-foreground">{total}</span>
      </p>
      <div className="flex items-center gap-1">
        <button
          onClick={() => onPage(page - 1)}
          disabled={page <= 1}
          className="rounded-md px-2.5 py-1 hover:bg-accent disabled:pointer-events-none disabled:opacity-40"
        >
          Previous
        </button>
        <span className="px-2 text-muted-foreground">
          Page {page} of {pages}
        </span>
        <button
          onClick={() => onPage(page + 1)}
          disabled={page >= pages}
          className="rounded-md px-2.5 py-1 hover:bg-accent disabled:pointer-events-none disabled:opacity-40"
        >
          Next
        </button>
      </div>
    </div>
  )
}
