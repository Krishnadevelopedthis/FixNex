import { Navigate, Route, Routes } from "react-router-dom"
import { Loader2, ShieldAlert } from "lucide-react"
import { AppLayout } from "@/layouts/AppLayout"
import { ErrorBoundary } from "@/components/error-boundary"
import { useAuth } from "@/hooks/useAuth"
import { Button } from "@/components/ui/button"

import LoginPage from "@/pages/Login"
import DashboardPage from "@/pages/Dashboard"
import AssessmentsPage from "@/pages/Assessments"
import AssessmentDetailPage from "@/pages/AssessmentDetail"
import AssetsPage from "@/pages/Assets"
import TargetsPage from "@/pages/Targets"
import ScansPage from "@/pages/Scans"
import ScanDetailPage from "@/pages/ScanDetail"
import FindingsPage from "@/pages/Findings"
import FindingDetailPage from "@/pages/FindingDetail"
import RemediationPage from "@/pages/Remediation"
import ReportsPage from "@/pages/Reports"
import AuditPage from "@/pages/Audit"
import UsersPage from "@/pages/admin/Users"
import RolesPage from "@/pages/admin/Roles"
import SystemPage from "@/pages/admin/System"
import SettingsPage from "@/pages/admin/Settings"

function FullPageLoader() {
  return (
    <div className="flex h-screen items-center justify-center">
      <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
    </div>
  )
}

function RequireAuth({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth()
  if (loading) return <FullPageLoader />
  if (!user) return <Navigate to="/login" replace />
  return <>{children}</>
}

/** Blocks a route when the signed-in role lacks the permission it needs. */
function RequirePermission({ permission, children }: { permission: string; children: React.ReactNode }) {
  const { can } = useAuth()
  if (!can(permission)) {
    return (
      <div className="flex flex-col items-center justify-center gap-3 py-24 text-center">
        <div className="rounded-full bg-destructive/10 p-4">
          <ShieldAlert className="h-7 w-7 text-destructive" />
        </div>
        <div className="space-y-1">
          <p className="text-lg font-semibold">Access denied</p>
          <p className="max-w-md text-sm text-muted-foreground">
            Your role does not include the <code className="font-mono text-xs">{permission}</code>{" "}
            permission required to view this page.
          </p>
        </div>
        <Button variant="outline" onClick={() => window.history.back()}>Go back</Button>
      </div>
    )
  }
  return <>{children}</>
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        element={
          <RequireAuth>
            <ErrorBoundary>
              <AppLayout />
            </ErrorBoundary>
          </RequireAuth>
        }
      >
        <Route index element={<DashboardPage />} />
        <Route path="assessments" element={<RequirePermission permission="assessment:view"><AssessmentsPage /></RequirePermission>} />
        <Route path="assessments/:id" element={<RequirePermission permission="assessment:view"><AssessmentDetailPage /></RequirePermission>} />
        <Route path="assets" element={<RequirePermission permission="asset:view"><AssetsPage /></RequirePermission>} />
        <Route path="targets" element={<RequirePermission permission="target:view"><TargetsPage /></RequirePermission>} />
        <Route path="scans" element={<RequirePermission permission="scan:view"><ScansPage /></RequirePermission>} />
        <Route path="scans/:id" element={<RequirePermission permission="scan:view"><ScanDetailPage /></RequirePermission>} />
        <Route path="findings" element={<RequirePermission permission="finding:view"><FindingsPage /></RequirePermission>} />
        <Route path="findings/:id" element={<RequirePermission permission="finding:view"><FindingDetailPage /></RequirePermission>} />
        <Route path="remediation" element={<RequirePermission permission="remediation:view"><RemediationPage /></RequirePermission>} />
        <Route path="reports" element={<RequirePermission permission="report:view"><ReportsPage /></RequirePermission>} />
        <Route path="audit" element={<RequirePermission permission="audit:view"><AuditPage /></RequirePermission>} />
        <Route path="admin/users" element={<RequirePermission permission="user:view"><UsersPage /></RequirePermission>} />
        <Route path="admin/roles" element={<RequirePermission permission="user:view"><RolesPage /></RequirePermission>} />
        <Route path="admin/system" element={<RequirePermission permission="system:view"><SystemPage /></RequirePermission>} />
        <Route path="admin/settings" element={<RequirePermission permission="settings:manage"><SettingsPage /></RequirePermission>} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
