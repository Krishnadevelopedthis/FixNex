import * as React from "react"
import * as DialogPrimitive from "@radix-ui/react-dialog"
import { AnimatePresence, motion } from "motion/react"
import { X } from "lucide-react"
import { cn } from "@/lib/utils"
import {
  TRANSITION, dialogVariants, dialogVariantsReduced, fade, useMotionPrefs,
} from "@/lib/motion"

/**
 * Radix unmounts dialog content on close, which leaves no exit animation to play.
 * Mirroring the open state into context lets AnimatePresence hold the content in
 * the tree just long enough to animate out, without every call site changing.
 */
const DialogOpenContext = React.createContext(false)

function Dialog({
  open, defaultOpen, onOpenChange, children, ...props
}: React.ComponentPropsWithoutRef<typeof DialogPrimitive.Root>) {
  const [internal, setInternal] = React.useState(defaultOpen ?? false)
  const isOpen = open ?? internal
  return (
    <DialogPrimitive.Root
      {...props}
      open={isOpen}
      onOpenChange={(next) => {
        if (open === undefined) setInternal(next)
        onOpenChange?.(next)
      }}
    >
      <DialogOpenContext.Provider value={isOpen}>{children}</DialogOpenContext.Provider>
    </DialogPrimitive.Root>
  )
}

const DialogTrigger = DialogPrimitive.Trigger
const DialogClose = DialogPrimitive.Close

const DialogContent = React.forwardRef<
  React.ElementRef<typeof DialogPrimitive.Content>,
  React.ComponentPropsWithoutRef<typeof DialogPrimitive.Content> & { size?: "sm" | "md" | "lg" | "xl" }
>(({ className, children, size = "md", ...props }, ref) => {
  const open = React.useContext(DialogOpenContext)
  const { reduced, transition } = useMotionPrefs()

  return (
    <AnimatePresence>
      {open && (
        <DialogPrimitive.Portal forceMount>
          <DialogPrimitive.Overlay asChild forceMount>
            <motion.div
              variants={fade}
              initial="hidden" animate="visible" exit="hidden"
              transition={transition(TRANSITION.fast)}
              className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm"
            />
          </DialogPrimitive.Overlay>

          <DialogPrimitive.Content ref={ref} asChild forceMount {...props}>
            <motion.div
              variants={reduced ? dialogVariantsReduced : dialogVariants}
              initial="hidden" animate="visible" exit="hidden"
              transition={transition(TRANSITION.base)}
              className={cn(
                "fixed left-1/2 top-1/2 z-50 grid w-[calc(100vw-2rem)] gap-4",
                "max-h-[90vh] overflow-y-auto rounded-lg border bg-card p-6 shadow-xl",
                { sm: "max-w-sm", md: "max-w-lg", lg: "max-w-2xl", xl: "max-w-4xl" }[size],
                className
              )}
            >
              {children}
              <DialogPrimitive.Close className="absolute right-4 top-4 rounded-sm opacity-60 transition-opacity hover:opacity-100 focus:outline-none focus:ring-2 focus:ring-ring">
                <X className="h-4 w-4" />
                <span className="sr-only">Close</span>
              </DialogPrimitive.Close>
            </motion.div>
          </DialogPrimitive.Content>
        </DialogPrimitive.Portal>
      )}
    </AnimatePresence>
  )
})
DialogContent.displayName = DialogPrimitive.Content.displayName

const DialogHeader = ({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) => (
  <div className={cn("flex flex-col space-y-1.5 pr-6", className)} {...props} />
)
const DialogFooter = ({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) => (
  <div className={cn("flex flex-col-reverse gap-2 sm:flex-row sm:justify-end", className)} {...props} />
)

const DialogTitle = React.forwardRef<
  React.ElementRef<typeof DialogPrimitive.Title>,
  React.ComponentPropsWithoutRef<typeof DialogPrimitive.Title>
>(({ className, ...props }, ref) => (
  <DialogPrimitive.Title ref={ref} className={cn("text-lg font-semibold leading-none tracking-tight", className)} {...props} />
))
DialogTitle.displayName = DialogPrimitive.Title.displayName

const DialogDescription = React.forwardRef<
  React.ElementRef<typeof DialogPrimitive.Description>,
  React.ComponentPropsWithoutRef<typeof DialogPrimitive.Description>
>(({ className, ...props }, ref) => (
  <DialogPrimitive.Description ref={ref} className={cn("text-sm text-muted-foreground", className)} {...props} />
))
DialogDescription.displayName = DialogPrimitive.Description.displayName

export {
  Dialog, DialogTrigger, DialogClose, DialogContent, DialogHeader,
  DialogFooter, DialogTitle, DialogDescription,
}
