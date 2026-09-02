/** Types mirroring the FixNex API schemas. */

export type Role =
  | "ADMIN" | "SECURITY_LEAD" | "SECURITY_ENGINEER" | "ANALYST" | "VIEWER" | "DEVELOPER"

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL"

export interface UserBrief {
  id: number
  full_name: string
  email: string
  role: Role
}

export interface CurrentUser extends UserBrief {
  role_label: string
  job_title?: string | null
  is_active: boolean
  is_demo?: boolean
  last_login_at?: string | null
  permissions: string[]
}

export interface TokenResponse {
  access_token: string
  refresh_token: string
  token_type: string
  expires_in: number
  user: CurrentUser
}

export interface Page<T> {
  items: T[]
  total: number
  page: number
  page_size: number
  pages: number
}

export interface SeverityBreakdown {
  CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number; INFORMATIONAL: number
}

export interface AssessmentStats {
  targets: number
  scans: number
  findings_total: number
  findings_open: number
  findings_closed: number
  findings_false_positive: number
  severity: SeverityBreakdown
  remediation_progress: number
  overdue: number
  highest_risk_level?: string | null
}

export interface Assessment {
  id: number
  reference: string
  name: string
  description?: string | null
  client_name?: string | null
  start_date?: string | null
  end_date?: string | null
  status: string
  methodology?: string | null
  notes?: string | null
  engagement_type?: string | null
  tags: string[]
  is_demo: boolean
  created_at: string
  updated_at: string
  created_by?: UserBrief | null
  members: { id: number; user_id: number; role_in_assessment?: string | null; user: UserBrief }[]
  stats?: AssessmentStats | null
}

export interface ScopeRule {
  id: number
  assessment_id: number
  rule_type: string
  value: string
  is_exclusion: boolean
  note?: string | null
  created_at: string
  created_by?: UserBrief | null
}

export interface Asset {
  id: number
  reference: string
  name: string
  description?: string | null
  asset_type: string
  owner?: string | null
  business_unit?: string | null
  primary_url?: string | null
  criticality: string
  data_sensitivity: string
  exposure: string
  technologies: { name: string; version?: string | null; category?: string }[]
  tags: string[]
  is_demo: boolean
  created_at: string
  open_findings: number
  highest_severity?: string | null
}

export interface Target {
  id: number
  reference: string
  assessment_id: number
  asset_id?: number | null
  asset_name?: string | null
  name: string
  target_type: string
  value: string
  hostname?: string | null
  port?: number | null
  base_path?: string | null
  description?: string | null
  status: string
  authorization_confirmed: boolean
  authorization_statement?: string | null
  authorized_at?: string | null
  authorized_by?: UserBrief | null
  technologies: { name: string; version?: string | null }[]
  is_demo: boolean
  created_at: string
  endpoint_count: number
  findings_count: number
  last_scan_at?: string | null
}

export interface ScannerRun {
  id: number
  scanner: string
  scanner_label?: string | null
  status: string
  started_at?: string | null
  completed_at?: string | null
  duration_ms?: number | null
  exit_code?: number | null
  raw_findings_count: number
  error_message?: string | null
  tool_version?: string | null
  command_summary?: string | null
  metrics: Record<string, unknown>
}

export interface Scan {
  id: number
  reference: string
  assessment_id: number
  assessment_name?: string | null
  target_id: number
  target_name?: string | null
  target_value?: string | null
  profile: string
  status: string
  progress: number
  current_operation?: string | null
  requested_scanners: string[]
  findings_count: number
  raw_findings_count: number
  duplicates_merged: number
  started_at?: string | null
  completed_at?: string | null
  duration_seconds?: number | null
  error_message?: string | null
  task_runner?: string | null
  created_at: string
  created_by?: UserBrief | null
  scanner_runs: ScannerRun[]
}

export interface ScannerInfo {
  name: string
  label: string
  description: string
  kind: "builtin" | "external"
  available: boolean
  availability_detail: string
  version?: string | null
  requires?: string | null
}

export interface ScanProfileInfo {
  name: string
  label: string
  description: string
  scanners: string[]
  invasive: boolean
  estimated_duration: string
}

export interface SLAInfo {
  due_at?: string | null
  status: string
  hours_remaining?: number | null
  breached: boolean
}

export interface RiskBreakdown {
  base_cvss?: number | null
  risk_score?: number | null
  risk_level?: string | null
  impact?: string | null
  likelihood?: string | null
  factors: Record<string, unknown>
  explanation: string[]
  disclaimer: string
}

export interface Evidence {
  id: number
  finding_id: number
  filename: string
  content_type: string
  size_bytes: number
  file_hash: string
  description?: string | null
  version: number
  supersedes_id?: number | null
  is_current: boolean
  annotations: Annotation[]
  created_at: string
  uploaded_by?: UserBrief | null
  download_url?: string | null
}

export interface Annotation {
  id: string
  kind: "rect" | "arrow" | "highlight" | "text"
  x: number
  y: number
  width?: number
  height?: number
  x2?: number
  y2?: number
  text?: string
  color?: string
}

export interface Remediation {
  id: number
  finding_id: number
  status: string
  priority: string
  recommendation?: string | null
  developer_notes?: string | null
  fix_summary?: string | null
  assigned_to?: UserBrief | null
  assigned_by?: UserBrief | null
  assigned_at?: string | null
  sla_due_at?: string | null
  started_at?: string | null
  ready_for_retest_at?: string | null
  resolved_at?: string | null
  reopened_count: number
  sla?: SLAInfo | null
}

export interface Retest {
  id: number
  finding_id: number
  result: "PASS" | "FAIL"
  summary?: string | null
  method?: string | null
  performed_at?: string | null
  performed_by?: UserBrief | null
  approved_at?: string | null
  approved_by?: UserBrief | null
  created_at: string
}

export interface FindingHistoryEntry {
  id: number
  event_type: string
  actor_name?: string | null
  from_status?: string | null
  to_status?: string | null
  note?: string | null
  event_metadata: Record<string, unknown>
  created_at: string
}

export interface FindingComment {
  id: number
  body: string
  created_at: string
  user?: UserBrief | null
}

export interface FindingSource {
  id: number
  scanner: string
  scanner_label?: string | null
  scan_job_id?: number | null
  raw_title?: string | null
  raw_severity?: string | null
  confidence: number
  created_at: string
}

export interface Finding {
  id: number
  reference: string
  title: string
  assessment_id: number
  severity: Severity
  cvss_score?: number | null
  risk_level?: string | null
  status: string
  verification_status: string
  primary_source: string
  source_count: number
  data_origin: "REAL_SCAN" | "MANUAL" | "SEEDED_DEMO"
  is_demo: boolean
  cwe_id?: string | null
  cve_ids: string[]
  target_id?: number | null
  target_name?: string | null
  endpoint?: string | null
  assigned_to?: UserBrief | null
  priority?: string | null
  sla?: SLAInfo | null
  updated_at: string
  created_at: string
}

export interface CVEDetail {
  cve_id: string
  description?: string | null
  cvss_score?: number | null
  cvss_vector?: string | null
  severity?: string | null
  published?: string | null
  url?: string | null
  enriched?: boolean
  detail?: string
}

export interface FindingDetail extends Finding {
  description?: string | null
  category?: string | null
  parameter?: string | null
  http_method?: string | null
  technical_details?: string | null
  request_snippet?: string | null
  response_snippet?: string | null
  remediation_recommendation?: string | null
  references: string[]
  cvss_vector?: string | null
  cvss_version?: string | null
  cwe_name?: string | null
  cve_details: CVEDetail[]
  confidence: number
  duplicate_hits: number
  correlation_key?: string | null
  verification_note?: string | null
  false_positive_reason?: string | null
  verified_at?: string | null
  verified_by?: UserBrief | null
  is_suppressed: boolean
  suppression_reason?: string | null
  first_seen_at?: string | null
  last_seen_at?: string | null
  closed_at?: string | null
  target_value?: string | null
  risk?: RiskBreakdown | null
  sources: FindingSource[]
  evidence: Evidence[]
  history: FindingHistoryEntry[]
  comments: FindingComment[]
  remediation?: Remediation | null
  retests: Retest[]
  available_transitions: string[]
}

export interface Report {
  id: number
  reference: string
  assessment_id: number
  assessment_name?: string | null
  title: string
  format: string
  status: string
  filename?: string | null
  size_bytes: number
  file_hash?: string | null
  engine?: string | null
  error_message?: string | null
  created_at: string
  generated_by?: UserBrief | null
  download_url?: string | null
}

export interface AuditLog {
  id: number
  action: string
  actor_email?: string | null
  actor_role?: string | null
  resource_type?: string | null
  resource_id?: string | null
  assessment_id?: number | null
  description?: string | null
  old_value?: Record<string, unknown> | null
  new_value?: Record<string, unknown> | null
  ip_address?: string | null
  created_at: string
  user?: UserBrief | null
}

export interface CountByKey { key: string; label?: string | null; count: number }

export interface Dashboard {
  generated_at: string
  demo_mode: boolean
  assessments: { total: number; active: number; draft: number; completed: number; archived: number }
  findings: {
    total: number; critical: number; high: number; medium: number; low: number
    informational: number; confirmed: number; false_positive: number
    needs_verification: number; closed: number
  }
  remediation: {
    open: number; in_progress: number; ready_for_retest: number; retesting: number
    resolved: number; reopened: number; overdue: number; due_soon: number; progress_percent: number
  }
  scans: { total: number; running: number; queued: number; completed: number; failed: number }
  severity_distribution: CountByKey[]
  risk_distribution: CountByKey[]
  cvss_distribution: CountByKey[]
  status_distribution: CountByKey[]
  top_risky_assets: {
    target_id?: number | null; asset_id?: number | null; name: string; value?: string | null
    criticality?: string | null; open_findings: number; max_severity?: string | null
    risk_score?: number | null
  }[]
  recent_scans: {
    id: number; reference: string; target_name?: string | null; profile: string
    status: string; progress: number; findings_count: number; created_at: string
  }[]
  recent_activity: {
    id: number; action: string; actor?: string | null; description?: string | null
    resource_type?: string | null; resource_id?: string | null; created_at: string
  }[]
  trend: { date: string; discovered: number; closed: number }[]
  risk_heatmap: { impact: string; likelihood: string; count: number }[]
  scanner_availability: Record<string, unknown>[]
  posture?: PostureScore | null
  asset_heatmap?: AssetHeatmap | null
}

export interface PostureFactor {
  key: string
  label: string
  count: number
  penalty: number
  max_penalty: number
  explanation: string
}

export interface PostureScore {
  score: number
  grade: string
  summary: string
  factors: PostureFactor[]
  totals: { findings: number; open: number; closed: number; resolution_rate: number }
  methodology: string
}

export interface HeatmapAsset {
  key: string
  name: string
  asset_id?: number | null
  target_id?: number | null
  criticality?: string | null
  targets: number
  counts: Record<string, number>
  total: number
}

export interface AssetHeatmap {
  severities: string[]
  assets: HeatmapAsset[]
  max_count: number
}

export interface ComponentHealth {
  name: string; label: string; kind: string; available: boolean
  detail: string; version?: string | null; required: boolean
}

export interface SystemHealth {
  healthy: boolean
  degraded_components: string[]
  components: ComponentHealth[]
  task_runner: string
  storage_backend: string
  offline_mode: boolean
  demo_mode: boolean
  version: string
}

export interface RoleInfo {
  role: Role
  label: string
  description: string
  permissions: string[]
}

/* ------------------------------------------------------------ attack paths */
export interface AttackPathNode {
  id: string
  kind: "finding" | "outcome"
  title: string
  severity: string
  finding_id?: number | null
  reference?: string | null
  category?: string | null
  cwe_id?: string | null
  status?: string | null
  endpoint?: string | null
  target_id?: number | null
  target_name?: string | null
  rule_id?: string | null
  rule_name?: string | null
  rationale?: string | null
}

export interface AttackPathEdge {
  id: string
  source: string
  target: string
  role: "prerequisite" | "enabler"
  rule_id: string
  label: string
}

export interface AttackPathStep {
  finding_id: number
  reference: string
  title: string
  severity: string
}

export interface AttackPath {
  rule_id: string
  rule_name: string
  outcome: string
  outcome_severity: string
  rationale: string
  target_id?: number | null
  target_name?: string | null
  prerequisite: AttackPathStep
  enabler: AttackPathStep
  same_surface: boolean
  escalates: boolean
}

export interface AttackPathResponse {
  assessment_id: number
  nodes: AttackPathNode[]
  edges: AttackPathEdge[]
  paths: AttackPath[]
  summary: {
    paths: number
    escalating_paths: number
    findings_considered: number
    findings_in_paths: number
    highest_outcome_severity?: string | null
    rules_evaluated: number
  }
  disclaimer: string
}

/* -------------------------------------------------------------- compliance */
export interface ComplianceControl {
  id: string
  title: string
  open_findings: number
  resolved_findings: number
  worst_open_severity?: string | null
  readiness: number
  finding_ids: number[]
}

export interface ComplianceFramework {
  key: string
  label: string
  controls_affected: number
  controls_at_risk: number
  readiness?: number | null
  controls: ComplianceControl[]
}

export interface OwaspCategory {
  id: string
  title: string
  open_findings: number
  resolved_findings: number
  worst_open_severity?: string | null
}

export interface ComplianceResponse {
  assessment_id: number
  frameworks: ComplianceFramework[]
  owasp_top_10: OwaspCategory[]
  coverage: {
    findings_considered: number
    findings_mapped: number
    findings_unmapped: number
    mapping_rate: number
    unmapped_cwes: string[]
    catalogue_size: number
  }
  disclaimer: string
}

/* --------------------------------------------------------------- AI triage */
export interface AITriageSuggestion {
  false_positive_confidence: number
  reasoning: string
  suggested_fix: string
  verification_steps: string
  model?: string | null
  effort?: string | null
  generated_at?: string | null
  input_tokens?: number | null
  output_tokens?: number | null
  cached: boolean
  disclaimer: string
}
