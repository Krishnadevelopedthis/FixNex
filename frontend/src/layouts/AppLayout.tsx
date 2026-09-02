import * as React from "react"
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom"
import { AnimatePresence, motion } from "motion/react"
import {
  Activity, BadgeCheck, Bug, ChevronDown, ClipboardList, Crosshair, FileText,
  FolderKanban, Gauge, LayoutDashboard, LogOut, Menu, Moon, Radar, Server,
  Settings, ShieldCheck, Sun, Users, Wrench, X,
} from "lucide-react"
import { useAuth } from "@/hooks/useAuth"
import { useTheme } from "@/hooks/useTheme"
import { cn, initials } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Tooltip } from "@/components/ui/misc"
import { TRANSITION, fadeUp, useMotionPrefs } from "@/lib/motion"

interface NavItem {
  to: string
  label: string
  icon: React.ComponentType<{ className?: string }>
  permission?: string
}

const PRIMARY_NAV: NavItem[] = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard },
  { to: "/assessments", label: "Assessments", icon: FolderKanban, permission: "assessment:view" },
  { to: "/assets", label: "Assets", icon: Server, permission: "asset:view" },
  { to: "/targets", label: "Targets", icon: Crosshair, permission: "target:view" },
  { to: "/scans", label: "Scans", icon: Radar, permission: "scan:view" },
  { to: "/findings", label: "Findings", icon: Bug, permission: "finding:view" },
  { to: "/remediation", label: "Remediation", icon: Wrench, permission: "remediation:view" },
  { to: "/reports", label: "Reports", icon: FileText, permission: "report:view" },
  { to: "/audit", label: "Audit Logs", icon: ClipboardList, permission: "audit:view" },
]

const ADMIN_NAV: NavItem[] = [
  { to: "/admin/users", label: "Users", icon: Users, permission: "user:view" },
  { to: "/admin/roles", label: "Roles & Permissions", icon: BadgeCheck, permission: "user:view" },
  { to: "/admin/system", label: "System Health", icon: Gauge, permission: "system:view" },
  { to: "/admin/settings", label: "Settings", icon: Settings, permission: "settings:manage" },
]

function NavSection({ title, items, onNavigate }: {
  title?: string
  items: NavItem[]
  onNavigate?: () => void
}) {
  const { can } = useAuth()
  const visible = items.filter((item) => !item.permission || can(item.permission))
  if (!visible.length) return null

  return (
    <div className="space-y-1">
      {title && (
        <p className="px-3 pb-1 pt-4 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground/70">
          {title}
        </p>
      )}
      {visible.map(({ to, label, icon: Icon }) => (
        <NavLink
          key={to}
          to={to}
          end={to === "/"}
          onClick={onNavigate}
          className={({ isActive }) =>
            cn(
              "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
              isActive
                ? "bg-primary/10 text-primary"
                : "text-muted-foreground hover:bg-accent hover:text-foreground"
            )
          }
        >
          <Icon className="h-4 w-4 shrink-0" />
          <span className="truncate">{label}</span>
        </NavLink>
      ))}
    </div>
  )
}

export function AppLayout() {
  const { user, logout } = useAuth()
  const { theme, toggle } = useTheme()
  const navigate = useNavigate()
  const location = useLocation()
  const { transition, variants } = useMotionPrefs()
  const [mobileOpen, setMobileOpen] = React.useState(false)
  const [menuOpen, setMenuOpen] = React.useState(false)

  async function handleLogout() {
    await logout()
    navigate("/login", { replace: true })
  }

  const sidebar = (
    <>
      <div className="flex h-14 items-center gap-2.5 border-b px-5">
        <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary text-primary-foreground">
          <ShieldCheck className="h-4.5 w-4.5" />
        </div>
        <div className="min-w-0">
          <p className="truncate text-sm font-bold leading-tight tracking-tight">FixNex</p>
          <p className="truncate text-[10px] leading-tight text-muted-foreground">
            Security Assessment Platform
          </p>
        </div>
      </div>
      <nav className="flex-1 overflow-y-auto px-3 py-3">
        <NavSection items={PRIMARY_NAV} onNavigate={() => setMobileOpen(false)} />
        <NavSection title="Administration" items={ADMIN_NAV} onNavigate={() => setMobileOpen(false)} />
      </nav>
      <div className="border-t p-3">
        <div className="rounded-md bg-muted/50 p-3">
          <p className="text-[11px] font-medium text-muted-foreground">Authorized testing only</p>
          <p className="mt-1 text-[11px] leading-relaxed text-muted-foreground/80">
            Scans are restricted to targets inside an assessment's approved scope.
          </p>
        </div>
      </div>
    </>
  )

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      {/* Desktop sidebar */}
      <aside className="hidden w-60 shrink-0 flex-col border-r bg-card lg:flex">{sidebar}</aside>

      {/* Mobile drawer */}
      {mobileOpen && (
        <div className="fixed inset-0 z-50 lg:hidden">
          <div className="absolute inset-0 bg-black/60" onClick={() => setMobileOpen(false)} />
          <aside className="absolute left-0 top-0 flex h-full w-64 flex-col border-r bg-card">
            <button
              onClick={() => setMobileOpen(false)}
              className="absolute right-3 top-4 rounded-md p-1 hover:bg-accent"
            >
              <X className="h-4 w-4" />
            </button>
            {sidebar}
          </aside>
        </div>
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-14 shrink-0 items-center justify-between gap-3 border-b bg-card px-4 lg:px-6">
          <Button variant="ghost" size="icon" className="lg:hidden" onClick={() => setMobileOpen(true)}>
            <Menu className="h-5 w-5" />
          </Button>

          <div className="ml-auto flex items-center gap-2">
            <Tooltip label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}>
              <Button variant="ghost" size="icon" onClick={toggle} aria-label="Toggle theme">
                {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
              </Button>
            </Tooltip>

            <div className="relative">
              <button
                onClick={() => setMenuOpen((v) => !v)}
                onBlur={() => setTimeout(() => setMenuOpen(false), 150)}
                className="flex items-center gap-2 rounded-md py-1 pl-1 pr-2 text-left transition-colors hover:bg-accent"
              >
                <span className="flex h-7 w-7 items-center justify-center rounded-full bg-primary/15 text-[11px] font-semibold text-primary">
                  {initials(user?.full_name)}
                </span>
                <span className="hidden min-w-0 sm:block">
                  <span className="block truncate text-xs font-medium leading-tight">{user?.full_name}</span>
                  <span className="block truncate text-[10px] leading-tight text-muted-foreground">
                    {user?.role_label}
                  </span>
                </span>
                <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />
              </button>

              {menuOpen && (
                <div className="absolute right-0 top-full z-50 mt-1 w-60 overflow-hidden rounded-md border bg-popover shadow-lg animate-fade-in">
                  <div className="border-b px-3 py-2.5">
                    <p className="truncate text-sm font-medium">{user?.full_name}</p>
                    <p className="truncate text-xs text-muted-foreground">{user?.email}</p>
                    <Badge variant="muted" className="mt-1.5">{user?.role_label}</Badge>
                  </div>
                  <button
                    onMouseDown={handleLogout}
                    className="flex w-full items-center gap-2 px-3 py-2 text-sm text-destructive hover:bg-accent"
                  >
                    <LogOut className="h-4 w-4" /> Sign out
                  </button>
                </div>
              )}
            </div>
          </div>
        </header>

        <main className="flex-1 overflow-y-auto">
          {/* Keyed on pathname so each route enters as its own element.
              mode="wait" would blank the pane between routes; overlapping the
              short fade keeps navigation feeling immediate. */}
          <AnimatePresence initial={false}>
            <motion.div
              key={location.pathname}
              variants={variants(fadeUp)}
              initial="hidden"
              animate="visible"
              transition={transition(TRANSITION.base)}
              className="mx-auto w-full max-w-[1600px] px-4 py-6 lg:px-8"
            >
              <Outlet />
            </motion.div>
          </AnimatePresence>
        </main>
      </div>
    </div>
  )
}

/** Standard page heading used by every screen. */
export function PageHeader({ title, description, actions, badge }: {
  title: string
  description?: React.ReactNode
  actions?: React.ReactNode
  badge?: React.ReactNode
}) {
  return (
    <div className="mb-6 flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
      <div className="min-w-0 space-y-1">
        <div className="flex flex-wrap items-center gap-2">
          <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
          {badge}
        </div>
        {description && <p className="text-sm text-muted-foreground">{description}</p>}
      </div>
      {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
    </div>
  )
}

export { Activity }
