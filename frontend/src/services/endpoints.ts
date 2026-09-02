import { api } from "./api"
import type {
  AITriageSuggestion, Assessment, Asset, AttackPathResponse, AuditLog, ComplianceResponse, CurrentUser, Dashboard, Evidence, Finding, FindingDetail,
  Page, Remediation, Report, Retest, RoleInfo, Scan, ScannerInfo, ScanProfileInfo,
  ScopeRule, SystemHealth, Target, TokenResponse,
} from "@/types"

/* ------------------------------------------------------------------- auth */
export const authApi = {
  login: (email: string, password: string) =>
    api.post<TokenResponse>("/auth/login", { email, password }).then((r) => r.data),
  me: () => api.get<CurrentUser>("/auth/me").then((r) => r.data),
  logout: () => api.post("/auth/logout").then((r) => r.data),
  changePassword: (current_password: string, new_password: string) =>
    api.post("/auth/change-password", { current_password, new_password }).then((r) => r.data),
}

/* -------------------------------------------------------------- dashboard */
export const dashboardApi = {
  get: () => api.get<Dashboard>("/dashboard").then((r) => r.data),
}

/* ------------------------------------------------------------ assessments */
export const assessmentApi = {
  list: (params?: Record<string, unknown>) =>
    api.get<Page<Assessment>>("/assessments", { params }).then((r) => r.data),
  get: (id: number) => api.get<Assessment>(`/assessments/${id}`).then((r) => r.data),
  create: (payload: Record<string, unknown>) =>
    api.post<Assessment>("/assessments", payload).then((r) => r.data),
  update: (id: number, payload: Record<string, unknown>) =>
    api.patch<Assessment>(`/assessments/${id}`, payload).then((r) => r.data),
  remove: (id: number) => api.delete(`/assessments/${id}`).then((r) => r.data),
  setTeam: (id: number, members: { user_id: number; role_in_assessment?: string }[]) =>
    api.put<Assessment>(`/assessments/${id}/team`, { members }).then((r) => r.data),

  scope: (id: number) => api.get<ScopeRule[]>(`/assessments/${id}/scope`).then((r) => r.data),
  addScope: (id: number, payload: Record<string, unknown>) =>
    api.post<ScopeRule>(`/assessments/${id}/scope`, payload).then((r) => r.data),
  removeScope: (id: number, ruleId: number) =>
    api.delete(`/assessments/${id}/scope/${ruleId}`).then((r) => r.data),
  checkScope: (id: number, value: string) =>
    api.post<{ value: string; in_scope: boolean; reason: string; matched_rule?: ScopeRule | null }>(
      `/assessments/${id}/scope/check`, { value }
    ).then((r) => r.data),

  targets: (id: number) => api.get<Target[]>(`/assessments/${id}/targets`).then((r) => r.data),
  attackPaths: (id: number) =>
    api.get<AttackPathResponse>(`/assessments/${id}/attack-paths`).then((r) => r.data),
  compliance: (id: number) =>
    api.get<ComplianceResponse>(`/assessments/${id}/compliance`).then((r) => r.data),
  addTarget: (id: number, payload: Record<string, unknown>) =>
    api.post<Target>(`/assessments/${id}/targets`, payload).then((r) => r.data),
}

/* ---------------------------------------------------------------- targets */
export const targetApi = {
  list: (params?: Record<string, unknown>) =>
    api.get<Page<Target>>("/targets", { params }).then((r) => r.data),
  get: (id: number) => api.get<Target>(`/targets/${id}`).then((r) => r.data),
  update: (id: number, payload: Record<string, unknown>) =>
    api.patch<Target>(`/targets/${id}`, payload).then((r) => r.data),
  remove: (id: number) => api.delete(`/targets/${id}`).then((r) => r.data),
  endpoints: (id: number) => api.get(`/targets/${id}/endpoints`).then((r) => r.data),
  importOpenApi: (id: number, payload: Record<string, unknown>) =>
    api.post(`/targets/${id}/import-openapi`, payload).then((r) => r.data),
}

/* ----------------------------------------------------------------- assets */
export const assetApi = {
  list: (params?: Record<string, unknown>) =>
    api.get<Page<Asset>>("/assets", { params }).then((r) => r.data),
  get: (id: number) => api.get<Asset>(`/assets/${id}`).then((r) => r.data),
  create: (payload: Record<string, unknown>) => api.post<Asset>("/assets", payload).then((r) => r.data),
  update: (id: number, payload: Record<string, unknown>) =>
    api.patch<Asset>(`/assets/${id}`, payload).then((r) => r.data),
}

/* ------------------------------------------------------------------ scans */
export const scanApi = {
  list: (params?: Record<string, unknown>) =>
    api.get<Page<Scan>>("/scans", { params }).then((r) => r.data),
  get: (id: number) => api.get<Scan>(`/scans/${id}`).then((r) => r.data),
  create: (payload: Record<string, unknown>) => api.post<Scan>("/scans", payload).then((r) => r.data),
  cancel: (id: number) => api.post<Scan>(`/scans/${id}/cancel`).then((r) => r.data),
  scanners: () => api.get<ScannerInfo[]>("/scans/scanners").then((r) => r.data),
  importTools: () => api.get<string[]>("/scans/import/tools").then((r) => r.data),
  importSarif: (assessmentId: number, targetId: number, toolName: string, file: File) => {
    const form = new FormData()
    form.append("assessment_id", String(assessmentId))
    form.append("target_id", String(targetId))
    form.append("tool_name", toolName)
    form.append("file", file)
    return api
      .post<Scan>("/scans/import", form, { headers: { "Content-Type": "multipart/form-data" } })
      .then((r) => r.data)
  },
  profiles: () => api.get<ScanProfileInfo[]>("/scans/profiles").then((r) => r.data),
}

/* --------------------------------------------------------------- findings */
export const findingApi = {
  list: (params?: Record<string, unknown>) =>
    api.get<Page<Finding>>("/findings", { params }).then((r) => r.data),
  get: (id: number) => api.get<FindingDetail>(`/findings/${id}`).then((r) => r.data),
  create: (payload: Record<string, unknown>) =>
    api.post<FindingDetail>("/findings", payload).then((r) => r.data),
  update: (id: number, payload: Record<string, unknown>) =>
    api.patch<FindingDetail>(`/findings/${id}`, payload).then((r) => r.data),
  verify: (id: number, payload: { confirmed: boolean; reason?: string; note?: string }) =>
    api.post<FindingDetail>(`/findings/${id}/verify`, payload).then((r) => r.data),
  triage: (id: number, payload: { priority: string; note?: string }) =>
    api.post<FindingDetail>(`/findings/${id}/triage`, payload).then((r) => r.data),
  assign: (id: number, payload: Record<string, unknown>) =>
    api.post<FindingDetail>(`/findings/${id}/assign`, payload).then((r) => r.data),
  score: (id: number, payload: Record<string, unknown>) =>
    api.post<FindingDetail>(`/findings/${id}/score`, payload).then((r) => r.data),
  suppress: (id: number, payload: { suppressed: boolean; reason?: string }) =>
    api.post<FindingDetail>(`/findings/${id}/suppress`, payload).then((r) => r.data),
  aiTriage: (id: number, refresh = false) =>
    api.get<AITriageSuggestion>(`/findings/${id}/ai-triage`, { params: { refresh } })
      .then((r) => r.data),
  comment: (id: number, body: string) =>
    api.post(`/findings/${id}/comments`, { body }).then((r) => r.data),

  evidence: (id: number) => api.get<Evidence[]>(`/findings/${id}/evidence`).then((r) => r.data),
  uploadEvidence: (id: number, file: File, description?: string, supersedesId?: number) => {
    const form = new FormData()
    form.append("file", file)
    if (description) form.append("description", description)
    if (supersedesId) form.append("supersedes_id", String(supersedesId))
    return api
      .post<Evidence>(`/findings/${id}/evidence`, form, {
        headers: { "Content-Type": "multipart/form-data" },
      })
      .then((r) => r.data)
  },

  createRemediation: (id: number, payload: Record<string, unknown>) =>
    api.post<Remediation>(`/findings/${id}/remediation`, payload).then((r) => r.data),
  updateRemediation: (id: number, payload: Record<string, unknown>) =>
    api.patch<Remediation>(`/findings/${id}/remediation`, payload).then((r) => r.data),
  readyForRetest: (id: number, fix_summary?: string) =>
    api.post<Remediation>(`/findings/${id}/ready-for-retest`, { fix_summary }).then((r) => r.data),
  retest: (id: number, payload: { result: "PASS" | "FAIL"; summary?: string; method?: string }) =>
    api.post<Retest>(`/findings/${id}/retest`, payload).then((r) => r.data),
  retests: (id: number) => api.get<Retest[]>(`/findings/${id}/retests`).then((r) => r.data),
}

/* --------------------------------------------------------------- evidence */
export const evidenceApi = {
  get: (id: number) => api.get<Evidence>(`/evidence/${id}`).then((r) => r.data),
  remove: (id: number) => api.delete(`/evidence/${id}`).then((r) => r.data),
  verify: (id: number) =>
    api.get<{ evidence_id: number; recorded_hash: string; integrity_verified: boolean; detail: string }>(
      `/evidence/${id}/verify`
    ).then((r) => r.data),
  annotate: (id: number, annotations: unknown[]) =>
    api.put<Evidence>(`/evidence/${id}/annotations`, { annotations }).then((r) => r.data),
}

/* ------------------------------------------------------------ remediation */
export const remediationApi = {
  list: (params?: Record<string, unknown>) =>
    api.get<Page<Finding>>("/remediation", { params }).then((r) => r.data),
}

/* ---------------------------------------------------------------- reports */
export const reportApi = {
  list: (params?: Record<string, unknown>) =>
    api.get<Page<Report>>("/reports", { params }).then((r) => r.data),
  get: (id: number) => api.get<Report>(`/reports/${id}`).then((r) => r.data),
  create: (payload: Record<string, unknown>) => api.post<Report>("/reports", payload).then((r) => r.data),
}

/* ------------------------------------------------------------ audit/admin */
export const auditApi = {
  list: (params?: Record<string, unknown>) =>
    api.get<Page<AuditLog>>("/audit-logs", { params }).then((r) => r.data),
  actions: () => api.get<string[]>("/audit-logs/actions").then((r) => r.data),
}

export const userApi = {
  /** Active users only by default — assignment pickers should not offer
   *  deactivated accounts. Administration passes activeOnly: false. */
  list: (activeOnly = true) =>
    api.get<CurrentUser[]>("/users", { params: { active_only: activeOnly } }).then((r) => r.data),
  create: (payload: Record<string, unknown>) => api.post("/users", payload).then((r) => r.data),
  update: (id: number, payload: Record<string, unknown>) =>
    api.patch(`/users/${id}`, payload).then((r) => r.data),
  remove: (id: number) => api.delete(`/users/${id}`).then((r) => r.data),
  roles: () => api.get<RoleInfo[]>("/roles").then((r) => r.data),
}

export const systemApi = {
  health: () => api.get<SystemHealth>("/system/health").then((r) => r.data),
  slaSettings: () => api.get<Record<string, number>>("/system/settings/sla").then((r) => r.data),
  updateSla: (payload: Record<string, number>) =>
    api.put("/system/settings/sla", payload).then((r) => r.data),
  seedDemo: () => api.post("/system/demo/seed").then((r) => r.data),
}
