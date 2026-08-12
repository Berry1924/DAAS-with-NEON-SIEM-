export type UserRole = 'ADMIN' | 'ANALYST' | 'VIEWER';
export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type AlertStatus = 'NEW' | 'ACKNOWLEDGED' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE';
export type IncidentStatus = 'NEW' | 'ACKNOWLEDGED' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE';
export type CorrelationStatus = 'ACTIVE' | 'RESOLVED';
export type AuditResult = 'SUCCESS' | 'FAILURE' | 'DENIED';

export interface User {
  id?: string;
  username: string;
  display_name: string;
  role: UserRole;
  email?: string;
}

export interface Health {
  status: string;
  app: string;
  version: string;
  environment?: string;
}

export interface EventItem {
  id: string;
  timestamp: string;
  source_type: string;
  event_type: string;
  source_ip?: string;
  destination_ip?: string;
  hostname?: string;
  username?: string;
  action?: string;
  outcome: string;
  severity: Severity;
  source_event_id?: string;
  raw_event: Record<string, unknown>;
  event_metadata: Record<string, unknown>;
}

export interface EventPage {
  items: EventItem[];
  page: number;
  page_size: number;
  total: number;
  pages: number;
}

export interface AlertLink {
  alert_id: string;
  title: string;
  severity: Severity;
  risk_score: number;
  rule_id: string;
  correlation_role: string;
}

export interface EventEvidence {
  id: string;
  timestamp: string;
  source_type: string;
  event_type: string;
  source_ip?: string;
  destination_ip?: string;
  username?: string;
  hostname?: string;
  outcome: string;
  severity: Severity;
}

export interface RiskFactor {
  type: string;
  label: string;
  points: number;
}

export interface RiskExplanation {
  base_risk: number;
  correlation_bonus: number;
  compromise_indicator_bonus: number;
  privilege_escalation_bonus: number;
  asset_criticality_modifier: number;
  final_score: number;
  severity: Severity;
  factors: RiskFactor[];
  explanation_summary: string;
}

export interface IncidentSummary {
  id: string;
  incident_key: string;
  title: string;
  incident_type: string;
  description?: string;
  severity: Severity;
  risk_score: number;
  status: IncidentStatus;
  assigned_to?: string;
  assignee_name?: string;
  source_ip?: string;
  destination_ip?: string;
  username?: string;
  correlation_rule?: string;
  first_seen_at: string;
  last_seen_at: string;
  created_at: string;
  updated_at: string;
  resolved_at?: string;
}

export interface TimelineEntry {
  id: string;
  incident_id: string;
  timestamp: string;
  entry_type: string;
  event_id?: string;
  alert_id?: string;
  title: string;
  summary?: string;
  timeline_metadata: Record<string, unknown>;
  created_at: string;
}

export interface IncidentNote {
  id: string;
  incident_id: string;
  author_id: string;
  author_name?: string;
  body: string;
  created_at: string;
  updated_at: string;
}

export interface IncidentDetail extends IncidentSummary {
  risk_explanation: RiskExplanation;
  linked_alerts: AlertLink[];
  linked_events: EventEvidence[];
  timeline: TimelineEntry[];
  notes: IncidentNote[];
}

export interface IncidentPage {
  items: IncidentSummary[];
  page: number;
  page_size: number;
  total: number;
  pages: number;
}

export interface AuditLog {
  id: string;
  timestamp: string;
  actor_id?: string;
  actor_name?: string;
  action: string;
  target_type?: string;
  target_id?: string;
  result: AuditResult;
  request_id?: string;
  source_ip?: string;
  audit_metadata: Record<string, unknown>;
}

export interface AuditPage {
  items: AuditLog[];
  page: number;
  page_size: number;
  total: number;
  pages: number;
}

export interface SeverityCountItem {
  severity: Severity;
  count: number;
}

export interface RuleTriggerCountItem {
  rule_id: string;
  name?: string;
  count: number;
}

export interface HourlyBucketItem {
  hour: string;
  count: number;
}

export interface DashboardRecentIncident {
  id: string;
  incident_key: string;
  title: string;
  severity: Severity;
  risk_score: number;
  status: IncidentStatus;
  created_at: string;
  assigned_to?: string;
  assignee_name?: string;
}

export interface DashboardSummary {
  total_events_24h: number;
  active_alerts_by_severity: SeverityCountItem[];
  open_incidents: number;
  top_detection_rules: RuleTriggerCountItem[];
  recent_incidents: DashboardRecentIncident[];
  event_trend: HourlyBucketItem[];
}

