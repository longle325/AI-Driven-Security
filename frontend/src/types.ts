export type Dict<T = unknown> = Record<string, T>;

export interface Summary {
  total_logs: number;
  detected_logs: number;
  total_alerts: number;
  label_distribution: Record<string, number>;
  severity_distribution: Record<string, number>;
  threat_distribution: Record<string, number>;
  latest_alert_time: string | null;
  metrics: Metrics;
  llm: {
    mode: string;
    provider: string;
    model: string;
    has_key: boolean;
  };
}

export interface Metrics {
  model?: string;
  samples?: number;
  labels?: string[];
  dataset?: string;
  trained_at?: string;
  accuracy?: number;
  precision?: number;
  recall?: number;
  f1_score?: number;
  feature_columns?: string[];
}

export interface LogEvent {
  timestamp: string;
  source_ip: string;
  user_id: string;
  event_type: string;
  endpoint: string;
  http_method: string;
  status_code: number;
  request_count_1m: number;
  failed_login_count_5m: number;
  unique_ports_1m: number;
  status_4xx_count_5m: number;
  status_5xx_count_5m: number;
  payload_risk_score: number;
  endpoint_risk_score: number;
  avg_request_interval: number;
  label: string;
  rule_prediction?: string;
  rule_reason?: string;
  rule_id?: string;
  ml_prediction?: string;
  ml_confidence?: number;
  evidence_ref?: string;
}

export interface Alert {
  alert_id: string;
  timestamp: string;
  source_ip: string;
  user_id: string;
  endpoint: string;
  event_type: string;
  threat_type: string;
  severity: string;
  rule_prediction: string;
  rule_reason: string;
  rule_id: string;
  ml_prediction: string;
  ml_confidence: number;
  recommended_action: string;
  evidence_ref: string;
  important_features?: Record<string, number | string>;
}

export interface MetricsPayload {
  metrics: Metrics;
  classification_report: string;
  feature_importance: Array<{ feature: string; importance: number }>;
}

export interface RuleVsAi {
  total: number;
  agreement: number;
  disagreement: number;
  agreement_rate: number;
  rule_counts: Record<string, number>;
  ml_counts: Record<string, number>;
  examples: LogEvent[];
}

export interface AdvisorResult {
  alert_id: string;
  mode: string;
  model: string | null;
  recommendation: {
    incident_summary?: string;
    threat_explanation?: string;
    severity_reasoning?: string;
    immediate_next_steps?: string[];
    investigation_steps?: string[];
    mitigation_actions?: string[];
    false_positive_checklist?: string[];
    evidence_to_collect?: string[];
    long_term_improvements?: string[];
    provider_error?: string;
  };
}

export interface EvidenceFile {
  name: string;
  size: number;
}

export interface CommandResponse<T = Record<string, unknown>> {
  ok: boolean;
  message: string;
  details: T;
}

export interface StreamStatus {
  total: number;
  processed: number;
  remaining: number;
  done: boolean;
}

export interface StreamStepDetails extends StreamStatus {
  event: LogEvent | null;
  detected: LogEvent | null;
  alert: Alert | null;
}
