export type HealthStatus = "ok" | "degraded" | "error";

export interface HealthCheckResponse {
  status: HealthStatus;
  checks: Record<string, string>;
}

export interface AssetSummary {
  id: string;
  agent_id: string | null;
  hostname: string;
  display_name: string | null;
  primary_ip: string | null;
  platform: string | null;
  os_family: string | null;
  os_version: string | null;
  architecture: string | null;
  criticality: string;
  environment_type: string;
  exposure_type: string;
  last_seen_at: string | null;
  component_count: number;
  exposure_count: number;
  ownership: AssetOwnership;
}

export interface AssetListPage {
  items: AssetSummary[];
  offset: number;
  limit: number;
  has_more: boolean;
  total: number;
  high_criticality_count: number;
  public_exposure_count: number;
  incomplete_ownership_count: number;
}

export type AssetOwnershipStatus = "complete" | "unassigned" | "system_incomplete";

export interface AssetOwnership {
  status: AssetOwnershipStatus;
  source: "manual" | "migration" | "agent_match" | null;
  updated_at: string | null;
  business_system: {
    id: string;
    code: string;
    name: string;
    status: string;
  } | null;
  responsible_person: {
    id: string;
    name: string;
    email: string | null;
    status: string;
  } | null;
  responsibility_team: {
    id: string;
    code: string;
    name: string;
    status: string;
  } | null;
}

export interface AssetComponent {
  id: string;
  component_name: string;
  component_type: string;
  version: string | null;
  source_type: string | null;
  install_path: string | null;
  evidence_ref: string | null;
}

export interface AssetExposure {
  id: string;
  exposure_kind: string;
  address: string | null;
  port: number | null;
  protocol: string;
  service_name: string | null;
  product: string | null;
  version: string | null;
  state: string;
  is_public: boolean;
  banner: string | null;
  evidence_ref: string | null;
}

export type FirewallEngine = "firewalld" | "ufw" | "iptables" | "nftables";
export type FirewallScope = "runtime" | "permanent";

export interface AssetFirewall {
  id: string;
  engine: FirewallEngine;
  role: "manager" | "backend" | "compatibility" | "standalone";
  backend: string | null;
  managed_by: string | null;
  effective: boolean;
  installed: boolean;
  runtime_state: "active" | "inactive" | "configured" | "unknown";
  service_enabled: boolean | null;
  collection_status:
    | "success"
    | "partial"
    | "unsupported"
    | "permission_denied"
    | "timeout"
    | "error";
  error_code: string | null;
  error_message: string | null;
  runtime_rule_count: number;
  permanent_rule_count: number;
  last_attempt_at: string;
  last_success_at: string | null;
}

export interface AssetFirewallList {
  items: AssetFirewall[];
  total: number;
}

export interface AssetFirewallRule {
  id: string;
  firewall_id: string;
  engine: FirewallEngine;
  scope: FirewallScope;
  family: string | null;
  table: string | null;
  chain: string | null;
  zone: string | null;
  order: number;
  rule_kind: string;
  action: string | null;
  protocol: string | null;
  source: string | null;
  destination: string | null;
  source_port: string | null;
  destination_port: string | null;
  in_interface: string | null;
  out_interface: string | null;
  state_match: string | null;
  comment: string | null;
  raw_rule: string;
}

export interface AssetFirewallRuleList {
  items: AssetFirewallRule[];
  total: number;
  page: number;
  page_size: number;
}

export interface AssetFirewallRaw {
  engine: FirewallEngine;
  scope: FirewallScope;
  content: string | null;
  collection_status: AssetFirewall["collection_status"];
  last_success_at: string | null;
}

export interface AssetSnapshotSummary {
  id: string;
  agent_id: string;
  agent_version: string | null;
  platform: string | null;
  collected_at: string;
  received_at: string;
  payload_hash: string;
  component_count: number;
  exposure_count: number;
  firewall_count: number;
  firewall_rule_count: number;
}

export interface AgentTaskStats {
  queued: number;
  in_progress: number;
  cancel_requested: number;
  cancelled: number;
  completed: number;
  failed: number;
  rejected: number;
  total: number;
}

export interface AgentStatus {
  agent_id: string;
  hostname: string | null;
  platform: string | null;
  version: string | null;
  status: string;
  last_heartbeat_at: string | null;
  last_snapshot_at: string | null;
  last_task_poll_at: string | null;
  last_error: string | null;
  created_at: string;
  updated_at: string;
}

export interface AgentSummary extends AgentStatus {
  asset_id: string | null;
  asset_hostname: string | null;
  asset_primary_ip: string | null;
  asset_last_seen_at: string | null;
  task_stats: AgentTaskStats;
}

export type AgentDetail = AgentSummary;

export interface LifecycleActionResult {
  status: string;
  agent_id: string | null;
  asset_id: string | null;
  asset_deleted: boolean;
  agent_deleted: boolean;
  agent_disabled: boolean;
  match_results_deleted: number;
  verification_tasks_deleted: number;
}

export type AgentEnrollmentTokenStatus = "active" | "expired" | "used_up" | "revoked";

export interface AgentEnrollmentToken {
  id: string;
  name: string;
  token_preview: string | null;
  status: AgentEnrollmentTokenStatus;
  expires_at: string | null;
  max_uses: number | null;
  used_count: number;
  created_by: string | null;
  created_by_display: string | null;
  revoked_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface AgentEnrollmentTokenCreateRequest {
  name: string;
  expires_at?: string | null;
  max_uses?: number | null;
}

export interface AgentEnrollmentTokenCreateResponse extends AgentEnrollmentToken {
  enrollment_token: string;
}

export interface AssetFreshness {
  last_snapshot_at: string | null;
  snapshot_age_seconds: number | null;
  stale_after_seconds: number;
  is_stale: boolean;
}

export interface AssetDetail extends AssetSummary {
  kernel_version: string | null;
  business_system: string | null;
  owner_team: string | null;
  owner_person: string | null;
  allow_auto_verify: boolean;
  allow_auto_remediate: boolean;
  snapshots_count: number;
  latest_snapshot: AssetSnapshotSummary | null;
  agent_status: AgentStatus | null;
  freshness: AssetFreshness;
  components: AssetComponent[];
  exposures: AssetExposure[];
}

export interface AssetMetadataUpdate {
  display_name?: string | null;
  environment_type?: string | null;
  exposure_type?: string | null;
  criticality?: string | null;
  allow_auto_verify?: boolean | null;
  allow_auto_remediate?: boolean | null;
}

export interface VulnerabilitySummary {
  id: string;
  canonical_id: string;
  title: string;
  vendor: string | null;
  product: string | null;
  severity_label: string | null;
  severity_cvss: number | null;
  kev_status: boolean;
  published_at: string | null;
  ai_enrichment_status: VulnerabilityAIEnrichmentStatus | null;
  information_completeness: VulnerabilityInformationCompleteness | null;
  match_readiness: VulnerabilityMatchReadiness | null;
  readiness_reasons: string[];
  readiness_missing_fields: string[];
  readiness_required_fields_present: string[];
  readiness_evidence_score: number | null;
  readiness_rule_version: string | null;
  readiness_updated_at: string | null;
  needs_ai_enrichment: boolean;
  needs_human_review: boolean;
}

export interface VulnerabilityListPage {
  items: VulnerabilitySummary[];
  offset: number;
  limit: number;
  has_more: boolean;
  total: number;
}

export type VulnerabilityInformationCompleteness =
  | "complete"
  | "partial"
  | "insufficient"
  | "conflicted";

export type VulnerabilityMatchReadiness =
  | "ready"
  | "needs_enrichment"
  | "needs_review"
  | "not_matchable";

export interface VulnerabilityReadiness {
  information_completeness: VulnerabilityInformationCompleteness;
  match_readiness: VulnerabilityMatchReadiness;
  reasons: string[];
  required_fields_present: string[];
  missing_fields: string[];
  evidence_score: number;
  rule_version: string;
  updated_at: string;
}

export interface VulnerabilityReadinessStats {
  total_count: number;
  ready_count: number;
  ready_kev_count: number;
  ready_high_severity_count: number;
  ready_max_cvss: number | null;
  needs_enrichment_count: number;
  needs_review_count: number;
  not_matchable_count: number;
  information_completeness_distribution: Record<string, number>;
  match_readiness_distribution: Record<string, number>;
  reason_distribution: Record<string, number>;
}

export interface VulnerabilitySourceSummary {
  id: string;
  source_name: string;
  event_type: string;
  external_id: string;
  source_url: string | null;
  severity_raw: string | null;
  published_at: string | null;
  references: string[];
  tags: string[];
}

export interface VulnerabilityAffectedScope {
  id: string;
  source_name: string;
  vendor: string | null;
  product: string;
  affected_versions: string | null;
  fixed_versions: string | null;
  source_url: string | null;
}

export interface VulnerabilityDetail extends VulnerabilitySummary {
  description: string | null;
  epss: number | null;
  kev_date_added: string | null;
  kev_due_date: string | null;
  known_ransomware_campaign_use: string | null;
  poc_status: boolean;
  wild_exploitation_status: boolean;
  affected_versions: string | null;
  fixed_versions: string | null;
  remediation: string | null;
  notes: string | null;
  sources: VulnerabilitySourceSummary[];
  affected_scopes: VulnerabilityAffectedScope[];
  readiness: VulnerabilityReadiness | null;
}

export type VulnerabilityReviewQueue =
  | "open"
  | "needs_enrichment"
  | "source_conflict"
  | "not_matchable"
  | "processed";

export interface VulnerabilityReviewResolution {
  id: string;
  reason_code: string;
  decision: string;
  note: string;
  subject_hash: string;
  actor_id: string | null;
  is_current: boolean;
  created_at: string;
}

export interface VulnerabilityReviewItem {
  vulnerability_id: string;
  canonical_id: string;
  title: string;
  vendor: string | null;
  product: string | null;
  severity_label: string | null;
  severity_cvss: number | null;
  kev_status: boolean;
  source_names: string[];
  readiness: VulnerabilityReadiness;
  primary_reason: string;
  review_state: string;
  active_decision: string | null;
  updated_at: string;
}

export interface VulnerabilityReviewListPage {
  items: VulnerabilityReviewItem[];
  offset: number;
  limit: number;
  has_more: boolean;
  total: number;
}

export interface VulnerabilityReviewSource {
  source_id: string;
  source_name: string;
  source_url: string | null;
  title: string | null;
  fields: Record<string, string | null>;
  references: string[];
}

export interface VulnerabilityReviewDetail {
  vulnerability: VulnerabilityDetail;
  current_fields: Record<string, string | null>;
  source_fields: VulnerabilityReviewSource[];
  affected_scopes: VulnerabilityAffectedScope[];
  resolutions: VulnerabilityReviewResolution[];
  subject_hashes: Record<string, string>;
  review_state: string;
  active_decision: string | null;
}

export interface VulnerabilityReviewResolutionCreate {
  reason_code: string;
  decision:
    | "confirmed_source_difference"
    | "excluded_from_matching"
    | "restored_to_matching"
    | "deferred";
  note: string;
  subject_hash: string;
}

export interface VulnerabilityCreate {
  canonical_id: string;
  title: string;
  vendor?: string | null;
  product?: string | null;
  description?: string | null;
  severity_label?: string | null;
  severity_cvss?: number | null;
  epss?: number | null;
  kev_status?: boolean;
  kev_date_added?: string | null;
  kev_due_date?: string | null;
  known_ransomware_campaign_use?: string | null;
  poc_status?: boolean;
  wild_exploitation_status?: boolean;
  affected_versions?: string | null;
  fixed_versions?: string | null;
  remediation?: string | null;
  published_at?: string | null;
  notes?: string | null;
}

export interface VulnerabilityUpdate {
  title?: string | null;
  vendor?: string | null;
  product?: string | null;
  description?: string | null;
  severity_label?: string | null;
  severity_cvss?: number | null;
  epss?: number | null;
  kev_status?: boolean | null;
  kev_date_added?: string | null;
  kev_due_date?: string | null;
  known_ransomware_campaign_use?: string | null;
  poc_status?: boolean | null;
  wild_exploitation_status?: boolean | null;
  affected_versions?: string | null;
  fixed_versions?: string | null;
  remediation?: string | null;
  published_at?: string | null;
  notes?: string | null;
}

export type RiskPriority = "critical" | "high" | "medium" | "low" | "none";

export type MatchStatus =
  | "affected"
  | "not_affected"
  | "needs_review"
  | "verified"
  | "suppressed";

export type MatchHandlingStatus =
  | "unprocessed"
  | "notified"
  | "remediating"
  | "pending_review"
  | "resolved"
  | "false_positive"
  | "risk_accepted";

export type MatchHandlingScope = "open" | "closed" | "all";

export type VerificationTaskStatus =
  | "queued"
  | "in_progress"
  | "cancel_requested"
  | "cancelled"
  | "completed"
  | "failed"
  | "rejected";

export interface RiskFactor {
  name: string;
  label: string;
  value: number;
  weight: number;
  weighted_score: number;
  evidence: string[];
}

export interface MatchEvidence {
  id: string;
  evidence_type: string;
  summary: string;
  raw_ref: string | null;
  confidence: number;
  details: Record<string, unknown>;
}

export interface MatchRuleTrace {
  rule_name: string;
  rule_version: string;
  executed: boolean;
  status: string;
  confidence: number;
  reason: string;
  uncertain_reason: string | null;
  input_summary: Record<string, unknown>;
  risk_scope: Record<string, unknown>;
  asset_context: Record<string, unknown>;
  evidence_count: number;
}

export interface VerificationEvidence {
  id: string;
  verification_task_id: string;
  evidence_type: string;
  summary: string;
  raw_ref: string | null;
  confidence: number;
  details: Record<string, unknown>;
  created_at: string;
}

export interface MatchResultHandlingRecord {
  id: string;
  match_result_id: string;
  action: "status_changed" | "reopened" | string;
  from_status: MatchHandlingStatus | null;
  to_status: MatchHandlingStatus;
  note: string | null;
  actor_id: string | null;
  actor_username: string | null;
  actor_display_name: string | null;
  created_at: string;
}

export interface MatchResultSummary {
  id: string;
  risk_code: string | null;
  vulnerability_id: string;
  vulnerability_canonical_id: string;
  vulnerability_title: string;
  vulnerability_product: string | null;
  vulnerability_kev_status: boolean;
  asset_id: string;
  asset_hostname: string;
  asset_agent_id: string | null;
  asset_agent_status: string | null;
  asset_last_seen_at: string | null;
  asset_snapshot_age_seconds: number | null;
  asset_is_stale: boolean;
  asset_exposure_type: string | null;
  asset_criticality: string | null;
  asset_has_public_exposure: boolean;
  ownership: AssetOwnership;
  status: MatchStatus;
  confidence: number;
  risk_score: number;
  risk_priority: RiskPriority;
  risk_model_version: string;
  risk_factors: RiskFactor[];
  risk_explanation: string | null;
  handling_status: MatchHandlingStatus;
  handling_note: string | null;
  handling_updated_by: string | null;
  handling_updated_at: string | null;
  handling_closed_at: string | null;
  match_reason: string | null;
  rule_version: string;
  last_evaluated_at: string | null;
  latest_verification_task_id: string | null;
  latest_verification_task_status: VerificationTaskStatus | null;
  verification_task_count: number;
  verification_evidence_count: number;
}

export interface MatchResultDetail extends MatchResultSummary {
  evidence: MatchEvidence[];
  matching_trace: MatchRuleTrace[];
  verification_evidence: VerificationEvidence[];
  handling_records: MatchResultHandlingRecord[];
}

export interface RiskConfig {
  model_version: string;
  weights: Record<string, number>;
  priority_thresholds: Record<string, number>;
  weight_total: number;
  warnings: string[];
}

export interface PlatformSettings {
  id: string;
  platform_name: string;
  platform_subtitle: string;
  logo_data_url: string | null;
  ai_enabled: boolean;
  ai_auto_enrich_enabled: boolean;
  ai_auto_accept_enabled: boolean;
  ai_auto_accept_policy: "strict" | "moderate" | "relaxed";
  ai_auto_accept_confidence: number;
  ai_web_auto_accept_confidence: number;
  ai_layer2_daily_limit: number;
  ai_batch_max_size: number;
  ai_allow_web_enrichment_default: boolean;
  auto_match_on_new_asset: boolean;
  auto_match_on_new_vulnerability: boolean;
  updated_at: string;
}

export interface PlatformSettingsUpdate {
  platform_name?: string | null;
  platform_subtitle?: string | null;
  logo_data_url?: string | null;
  ai_enabled?: boolean | null;
  ai_auto_enrich_enabled?: boolean | null;
  ai_auto_accept_enabled?: boolean | null;
  ai_auto_accept_policy?: "strict" | "moderate" | "relaxed" | null;
  ai_auto_accept_confidence?: number | null;
  ai_web_auto_accept_confidence?: number | null;
  ai_layer2_daily_limit?: number | null;
  ai_batch_max_size?: number | null;
  ai_allow_web_enrichment_default?: boolean | null;
  auto_match_on_new_asset?: boolean | null;
  auto_match_on_new_vulnerability?: boolean | null;
}

export interface AIPromptTemplate {
  template_key: string;
  system_prompt: string;
  user_prompt_template: string;
  output_contract: string;
  customized: boolean;
}

export interface AIProfile {
  id: string;
  profile_key: string;
  display_name: string;
  provider: string;
  model_vendor: string;
  base_url: string | null;
  model: string;
  enabled: boolean;
  supports_web_search: boolean;
  allow_external_network: boolean;
  json_mode: boolean;
  timeout_seconds: number;
  max_tokens: number | null;
  temperature: number;
  daily_call_limit: number | null;
  daily_token_limit: number | null;
  prompt_template: AIPromptTemplate | null;
  has_api_key: boolean;
  created_at: string;
  updated_at: string;
}

export interface AIProfileCreate {
  profile_key: string;
  display_name: string;
  provider: string;
  model_vendor?: string;
  base_url?: string | null;
  api_key?: string | null;
  model: string;
  enabled?: boolean;
  supports_web_search?: boolean;
  allow_external_network?: boolean;
  json_mode?: boolean;
  timeout_seconds?: number;
  max_tokens?: number | null;
  temperature?: number;
  daily_call_limit?: number | null;
  daily_token_limit?: number | null;
  prompt_template?: {
    system_prompt: string;
    user_prompt_template: string;
    output_contract: string;
  } | null;
}

export interface AIProfileUpdate {
  profile_key?: string | null;
  display_name?: string | null;
  provider?: string | null;
  model_vendor?: string | null;
  base_url?: string | null;
  api_key?: string | null;
  model?: string | null;
  enabled?: boolean | null;
  supports_web_search?: boolean | null;
  allow_external_network?: boolean | null;
  json_mode?: boolean | null;
  timeout_seconds?: number | null;
  max_tokens?: number | null;
  temperature?: number | null;
  daily_call_limit?: number | null;
  daily_token_limit?: number | null;
  prompt_template?: {
    system_prompt: string;
    user_prompt_template: string;
    output_contract: string;
  } | null;
}

export interface AIProfileTestResult {
  success: boolean;
  status: string;
  model: string;
  latency_ms: number | null;
  error_message: string | null;
}

export interface AIEnrichmentProfileStats {
  profile_id: string | null;
  profile_key: string | null;
  model: string | null;
  call_count: number;
  token_count: number;
  failed_count: number;
}

export interface AIEnrichmentStats {
  today_call_count: number;
  today_token_count: number;
  layer1_success_rate: number | null;
  layer2_success_rate: number | null;
  pending_review_count: number;
  accepted_count: number;
  rejected_count: number;
  auto_accepted_count: number;
  failed_count: number;
  insufficient_count: number;
  average_confidence: number | null;
  by_profile: AIEnrichmentProfileStats[];
}

export type VulnerabilityAIEnrichmentStatus =
  | "pending_review"
  | "insufficient"
  | "failed"
  | "accepted"
  | "rejected"
  | "auto_accepted"
  | "already_applied";

export interface VulnerabilityAIEnrichmentEvidence {
  field: string;
  source_type: string | null;
  source_url: string | null;
  quote: string | null;
  confidence: number | null;
}

export interface AIFieldEvidenceStatus {
  field_name: string;
  has_candidate: boolean;
  has_evidence: boolean;
  has_source_url: boolean;
  has_quote: boolean;
}

export interface AIEnrichmentQualityGate {
  quality_gate_status: string;
  quality_gate_reasons: string[];
  quality_gate_warnings: string[];
  field_evidence_status: AIFieldEvidenceStatus[];
  source_url_count: number;
  candidate_field_count: number;
  confidence: number | null;
  confidence_threshold: number | null;
  auto_accept_allowed: boolean;
  manual_accept_risk_level: string;
}

export interface VulnerabilityAIEnrichment {
  id: string;
  vulnerability_id: string;
  layer: string;
  source_mode: string;
  profile_id: string | null;
  model: string | null;
  input_hash: string;
  status: VulnerabilityAIEnrichmentStatus;
  vendor: string | null;
  product: string | null;
  affected_versions: string | null;
  fixed_versions: string | null;
  remediation: string | null;
  confidence: number | null;
  evidence: VulnerabilityAIEnrichmentEvidence[];
  source_urls: string[];
  conflicts: Record<string, unknown>[];
  raw_output: Record<string, unknown>;
  error_message: string | null;
  accepted_at: string | null;
  accepted_by: string | null;
  rejected_at: string | null;
  rejected_by: string | null;
  rejection_reason: string | null;
  quality_gate: AIEnrichmentQualityGate | null;
  created_at: string;
  updated_at: string;
}

export interface VulnerabilityAIEnrichmentTriggerRequest {
  layer?: "existing_data_extraction" | "web_enrichment" | "auto";
  async_mode?: boolean;
  allow_web_enrichment?: boolean;
  profile_key?: string | null;
  force_refresh?: boolean;
}

export interface VulnerabilityAIEnrichmentRunResponse {
  async_queued: boolean;
  task_id: string | null;
  enrichment: VulnerabilityAIEnrichment | null;
}

export type VulnerabilityAIEnrichmentAcceptField =
  | "vendor"
  | "product"
  | "affected_versions"
  | "fixed_versions"
  | "remediation";

export interface VulnerabilityAIEnrichmentAcceptRequest {
  fields: VulnerabilityAIEnrichmentAcceptField[];
  allow_overwrite?: boolean;
}

export interface VulnerabilityAIEnrichmentAcceptResponse {
  enrichment: VulnerabilityAIEnrichment;
  updated_fields: Record<string, { from: unknown; to: unknown }>;
  skipped_fields: Record<string, string>;
  matching_reevaluation_recommended: boolean;
}

export interface VulnerabilityAIEnrichmentRejectRequest {
  reason: string;
}

export interface VulnerabilityAIEnrichmentBatchFilters {
  match_readiness?: VulnerabilityMatchReadiness | null;
  missing_affected_versions?: boolean;
  missing_fixed_versions?: boolean;
  severity_labels?: string[];
  kev_status?: boolean | null;
  poc_status?: boolean | null;
  wild_exploitation_status?: boolean | null;
}

export interface VulnerabilityAIEnrichmentBatchRequest {
  filters?: VulnerabilityAIEnrichmentBatchFilters;
  layer?: "existing_data_extraction" | "web_enrichment" | "auto";
  limit?: number;
  allow_web_enrichment?: boolean;
  async_mode?: boolean;
  force_refresh?: boolean;
}

export interface VulnerabilityAIEnrichmentBatchResponse {
  batch_run_id: string;
  task_id: string | null;
  status: string;
  selected_count: number;
  skipped_count: number;
  message: string | null;
}

export interface VulnerabilityAIEnrichmentBatchRun {
  id: string;
  status: string;
  trigger_type: string;
  requested_by: string | null;
  task_id: string | null;
  filters: Record<string, unknown>;
  allow_web_enrichment: boolean;
  selected_count: number;
  processed_count: number;
  success_count: number;
  failed_count: number;
  skipped_count: number;
  pending_review_count: number;
  insufficient_count: number;
  recent_error: string | null;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface VulnerabilityAIEnrichmentBatchItem {
  vulnerability: VulnerabilityDetail;
  enrichment: VulnerabilityAIEnrichment | null;
  result_status: VulnerabilityAIEnrichmentStatus | "not_started";
}

export interface VulnerabilityAIEnrichmentBatchDetail {
  batch: VulnerabilityAIEnrichmentBatchRun;
  items: VulnerabilityAIEnrichmentBatchItem[];
}

export type NestedNumericMap = Record<string, Record<string, number>>;

export interface RuleNumericConfig {
  id: string;
  model_version: string;
  matching_confidences: NestedNumericMap;
  risk_factor_values: NestedNumericMap;
  risk_weights: Record<string, number>;
  risk_priority_thresholds: Record<string, number>;
  weight_total: number;
  warnings: string[];
  updated_at: string;
}

export interface RuleNumericConfigUpdate {
  matching_confidences?: NestedNumericMap;
  risk_factor_values?: NestedNumericMap;
  risk_weights?: Record<string, number>;
  risk_priority_thresholds?: Record<string, number>;
}

export interface RiskQueueQuery {
  risk_code?: string;
  status?: MatchStatus;
  min_risk_score?: number;
  risk_priority?: RiskPriority;
  asset_criticality?: string;
  exposure_type?: string;
  business_system_id?: string;
  responsible_person_id?: string;
  responsibility_team_id?: string;
  kev_only?: boolean;
  verification_state?: "verified" | "unverified" | "has_task" | "no_task";
  agent_status?: "online" | "offline" | "unknown";
  asset_freshness?: "fresh" | "stale";
  handling_status?: MatchHandlingStatus;
  handling_scope?: MatchHandlingScope;
  offset?: number;
  limit?: number;
}

export interface MatchResultsQuery {
  risk_code?: string;
  status?: MatchStatus;
  asset_id?: string;
  vulnerability_id?: string;
  offset?: number;
  limit?: number;
}

export interface MatchResultListPage {
  items: MatchResultSummary[];
  offset: number;
  limit: number;
  has_more: boolean;
  total: number;
  critical_count: number;
  unverified_count: number;
  stale_asset_count: number;
}

export interface MatchEvaluationRequest {
  asset_id?: string | null;
  vulnerability_id?: string | null;
}

export interface MatchEvaluationResponse {
  run_id: string;
  task_id: string | null;
  status: string;
  asset_id: string | null;
  vulnerability_id: string | null;
  total_count: number;
  processed_count: number;
  evaluated_count: number;
  skipped_count: number;
  failed_count: number;
  sample_result_ids: string[];
  recent_error: string | null;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface MatchResultHandlingUpdate {
  handling_status: MatchHandlingStatus;
  note?: string | null;
}

export interface MatchResultHandlingReopen {
  note?: string | null;
}

export interface VerificationTaskRequest {
  task_type: string;
  parameters: Record<string, unknown>;
  requested_by?: string | null;
}

export interface VerificationTask {
  id: string;
  asset_id: string;
  match_result_id: string;
  task_type: string;
  status: VerificationTaskStatus;
  parameters: Record<string, unknown>;
  requested_by: string | null;
  previous_task_id: string | null;
  assigned_at: string | null;
  cancel_requested_at: string | null;
  completed_at: string | null;
  error_code: string | null;
  error_message: string | null;
  created_at: string;
  updated_at: string;
}

export interface VerificationTaskSummary extends VerificationTask {
  asset_hostname: string | null;
  asset_agent_id: string | null;
  vulnerability_id: string | null;
  vulnerability_canonical_id: string | null;
  vulnerability_title: string | null;
  evidence_count: number;
  retry_count: number;
}

export interface VerificationTaskTimelineEvent {
  status: string;
  occurred_at: string;
  summary: string;
}

export interface VerificationTaskDetail extends VerificationTaskSummary {
  evidence: VerificationEvidence[];
  timeline: VerificationTaskTimelineEvent[];
}

export interface VerificationTasksQuery {
  status?: VerificationTaskStatus;
  agent_id?: string;
  asset_id?: string;
  vulnerability_id?: string;
  match_result_id?: string;
  task_type?: string;
  offset?: number;
  limit?: number;
}

export interface VerificationTaskListPage {
  items: VerificationTaskSummary[];
  offset: number;
  limit: number;
  has_more: boolean;
  total: number;
  active_count: number;
  failed_count: number;
  evidence_count: number;
}

export interface VerificationTaskActionRequest {
  requested_by?: string | null;
}

export interface VerificationEvidenceSummary extends VerificationEvidence {
  match_result_id: string;
  asset_id: string | null;
  asset_hostname: string | null;
  vulnerability_id: string | null;
  vulnerability_canonical_id: string | null;
  vulnerability_title: string | null;
}

export interface VerificationEvidenceQuery {
  verification_task_id?: string;
  match_result_id?: string;
  asset_id?: string;
  vulnerability_id?: string;
  evidence_type?: string;
  limit?: number;
}

export interface IntelCollectRequest {
  limit?: number | null;
  min_score?: number | null;
  async_mode: boolean;
  latest_only?: boolean;
}

export interface WatchVulnMonitorConfig {
  enabled: boolean;
  interval_seconds: number;
  limit: number | null;
  last_run_id: string | null;
  last_status: string | null;
  last_started_at: string | null;
  last_finished_at: string | null;
  last_error: string | null;
  next_run_at: string | null;
  updated_at: string;
}

export interface CisaKevMonitorConfig {
  enabled: boolean;
  interval_seconds: number;
  limit: number | null;
  latest_only: boolean;
  last_run_id: string | null;
  last_status: string | null;
  last_started_at: string | null;
  last_finished_at: string | null;
  last_error: string | null;
  next_run_at: string | null;
  updated_at: string;
}

export interface WatchVulnMonitorConfigUpdate {
  enabled?: boolean | null;
  interval_seconds?: number | null;
  limit?: number | null;
}

export interface CisaKevMonitorConfigUpdate {
  enabled?: boolean | null;
  interval_seconds?: number | null;
  limit?: number | null;
  latest_only?: boolean | null;
}

export interface IntelCollectionResult {
  status: string;
  source_name: string;
  run_id: string | null;
  fetched_count: number;
  stored_count: number;
  processed_count: number;
  skipped_count: number;
  failed_count: number;
  task_id: string | null;
  error_message: string | null;
  message: string | null;
}

export interface IntelSourceVulnerabilityCleanupResult {
  source_name: string;
  source_label: string | null;
  source_links_deleted: number;
  vulnerabilities_deleted: number;
  shared_vulnerabilities_retained: number;
  raw_events_deleted: number;
  collection_runs_deleted: number;
  match_results_deleted: number;
  verification_tasks_deleted: number;
  ai_enrichments_deleted: number;
  affected_scopes_deleted: number;
  review_resolutions_deleted: number;
}

export interface IntelCollectionRun {
  id: string;
  source_name: string;
  trigger_type: string;
  status: string;
  started_at: string;
  finished_at: string | null;
  fetched_count: number;
  stored_count: number;
  processed_count: number;
  skipped_count: number;
  failed_count: number;
  error_message: string | null;
  task_id: string | null;
  parameters: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface IntelSourceStatus {
  source_name: string;
  source_label: string | null;
  parent_source_name: string | null;
  enabled: boolean;
  last_run_id: string | null;
  last_status: string | null;
  last_started_at: string | null;
  last_finished_at: string | null;
  last_error: string | null;
  raw_event_count: number;
  processed_event_count: number;
  failed_event_count: number;
  vulnerability_count: number;
}

export interface IntelNormalizationQuality {
  has_canonical_id: boolean;
  has_product: boolean;
  has_fixed_version: boolean;
  has_severity: boolean;
  has_exploitation_signal: boolean;
}

export interface IntelRawEvent {
  id: string;
  provider: string;
  event_type: string;
  external_key: string;
  source_url: string | null;
  processing_status: string;
  received_at: string;
  processed_at: string | null;
  last_error: string | null;
  vulnerability_id: string | null;
  vulnerability_canonical_id: string | null;
  quality: IntelNormalizationQuality | null;
  created_at: string;
  updated_at: string;
}

export interface IntelRawEventNormalizeResult {
  raw_event_id: string;
  status: string;
  vulnerability_id: string | null;
  canonical_id: string | null;
}

export interface AuditLog {
  id: string;
  actor_type: string;
  actor_id: string | null;
  action: string;
  resource_type: string;
  resource_id: string | null;
  outcome: string;
  summary: string;
  details: Record<string, unknown>;
  created_at: string;
}

export interface HandlingAuditRecord {
  id: string;
  match_result_id: string;
  risk_code: string | null;
  vulnerability_id: string;
  vulnerability_canonical_id: string;
  vulnerability_title: string;
  asset_id: string;
  asset_hostname: string;
  action: string;
  from_status: MatchHandlingStatus | null;
  to_status: MatchHandlingStatus;
  note: string | null;
  actor_id: string | null;
  actor_username: string | null;
  actor_display_name: string | null;
  created_at: string;
}

export interface AuditLogsQuery {
  action?: string;
  actor_id?: string;
  resource_type?: string;
  resource_id?: string;
  outcome?: string;
  limit?: number;
}

export interface HandlingAuditRecordsQuery {
  actor_id?: string;
  match_result_id?: string;
  to_status?: MatchHandlingStatus;
  action?: string;
  limit?: number;
}

export type TaskCenterItemType =
  | "verification"
  | "intel_collection"
  | "risk_queue_item"
  | "ai_enrichment"
  | "match_evaluation";

export type TaskCenterStatusGroup =
  | "pending"
  | "running"
  | "success"
  | "failed"
  | "cancelled"
  | "attention";

export interface TaskCenterSummary {
  total: number;
  pending: number;
  running: number;
  success: number;
  failed: number;
  cancelled: number;
  attention: number;
  by_type: Record<string, number>;
}

export interface TaskCenterItem {
  id: string;
  raw_id: string;
  item_type: TaskCenterItemType;
  title: string;
  status: string;
  status_group: TaskCenterStatusGroup;
  source: string | null;
  trigger_type: string | null;
  asset_id: string | null;
  asset_name: string | null;
  agent_id: string | null;
  vulnerability_id: string | null;
  vulnerability_title: string | null;
  risk_priority: RiskPriority | string | null;
  risk_score: number | null;
  started_at: string | null;
  finished_at: string | null;
  updated_at: string;
  error_message: string | null;
  detail_path: string;
  available_actions: string[];
  metrics: Record<string, number>;
}

export interface TaskCenterItemsQuery {
  item_type?: TaskCenterItemType;
  status_group?: TaskCenterStatusGroup;
  status?: string;
  source?: string;
  trigger_type?: string;
  keyword?: string;
  limit?: number;
}

export type SystemEventCategory = "asset" | "intel" | "risk";
export type SystemEventLevel = "info" | "success" | "warning" | "error";

export interface SystemEvent {
  id: string;
  event_key: string;
  category: SystemEventCategory;
  event_type: string;
  level: SystemEventLevel;
  title: string;
  summary: string;
  details: Record<string, unknown>;
  target_type: string | null;
  target_id: string | null;
  target_query: Record<string, unknown>;
  occurred_at: string;
  created_at: string;
}

export interface AdminNotification {
  id: string;
  read_at: string | null;
  expires_at: string;
  created_at: string;
  event: SystemEvent;
}

export interface NotificationListPage {
  items: AdminNotification[];
  total: number;
  offset: number;
  limit: number;
}

export interface SystemEventListPage {
  items: SystemEvent[];
  total: number;
  offset: number;
  limit: number;
}

export interface NotificationHistoryQuery {
  category?: SystemEventCategory;
  event_type?: string;
  offset?: number;
  limit?: number;
}

export type SmtpSecurity = "starttls" | "ssl_tls" | "none";
export type EmailDeliveryStatus =
  | "queued"
  | "sending"
  | "retry_scheduled"
  | "sent"
  | "failed"
  | "skipped";
export type EmailTriggerType = "automatic" | "manual" | "test" | "manual_retry";

export interface EmailSettings {
  id: string;
  enabled: boolean;
  automatic_enabled: boolean;
  risk_threshold: Exclude<RiskPriority, "none">;
  retry_enabled: boolean;
  retry_delays_seconds: number[];
  smtp_host: string | null;
  smtp_port: number;
  smtp_security: SmtpSecurity;
  smtp_username: string | null;
  has_password: boolean;
  sender_name: string | null;
  sender_email: string | null;
  reply_to: string | null;
  timeout_seconds: number;
  subject_template: string;
  text_body_template: string;
  html_body_template: string;
  supported_template_variables: string[];
  version: number;
  updated_at: string;
}

export interface EmailSettingsUpdate {
  enabled?: boolean;
  automatic_enabled?: boolean;
  risk_threshold?: Exclude<RiskPriority, "none">;
  retry_enabled?: boolean;
  smtp_host?: string | null;
  smtp_port?: number;
  smtp_security?: SmtpSecurity;
  smtp_username?: string | null;
  smtp_password?: string | null;
  clear_password?: boolean;
  sender_name?: string | null;
  sender_email?: string | null;
  reply_to?: string | null;
  timeout_seconds?: number;
  subject_template?: string;
  text_body_template?: string;
  html_body_template?: string;
  expected_version?: number;
}

export interface EmailTemplatePreview {
  subject: string;
  text_body: string;
  html_body: string;
}

export interface EmailDeliveryAttempt {
  id: string;
  attempt_number: number;
  status: "sent" | "failed";
  error_message: string | null;
  started_at: string;
  finished_at: string;
}

export interface EmailDelivery {
  id: string;
  trigger_type: EmailTriggerType;
  status: EmailDeliveryStatus;
  source_event_id: string | null;
  retry_of_id: string | null;
  recipient_person_id: string | null;
  recipient_name: string | null;
  recipient_email: string | null;
  subject: string;
  risk_count: number;
  match_result_ids: string[];
  context: Record<string, unknown>;
  skip_reason: string | null;
  last_error: string | null;
  attempt_count: number;
  max_retries: number;
  next_attempt_at: string | null;
  last_attempt_at: string | null;
  sent_at: string | null;
  requested_by_user_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface EmailDeliveryDetail extends EmailDelivery {
  text_body: string;
  html_body: string;
  attempts: EmailDeliveryAttempt[];
}

export interface EmailDeliveryListPage {
  items: EmailDelivery[];
  total: number;
  offset: number;
  limit: number;
}

export interface EmailDeliveryQuery {
  status?: EmailDeliveryStatus;
  trigger_type?: EmailTriggerType;
  recipient_email?: string;
  offset?: number;
  limit?: number;
}

export interface EmailAction {
  delivery_id: string;
  status: EmailDeliveryStatus;
  message: string;
}
