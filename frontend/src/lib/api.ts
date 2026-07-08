const BASE = "/api";

export type Decision = "ALLOW" | "MONITOR" | "BLOCK";

export interface SessionView {
  session_id: string;
  user_id: string;
  device_id: string;
  ip_address: string;
  geo_country: string;
  os: string;
  created_at: string;
  last_seen_at: string;
  risk_score: number;
  posture_score: number;
  request_count: number;
  block_count: number;
  monitor_count: number;
  status: "ACTIVE" | "REVOKED" | "EXPIRED";
}

export interface EventView {
  id: string;
  ts: string;
  kind: "POSTURE" | "ACCESS" | "REVOKE" | "EXPIRE" | "PING";
  decision?: Decision;
  session_id?: string | null;
  user_id?: string | null;
  ip_address?: string | null;
  target_service?: string | null;
  risk_score?: number | null;
  reasons?: string[];
}

export interface Snapshot {
  active_sessions: number;
  total_decisions: number;
  allow_count: number;
  monitor_count: number;
  block_count: number;
  block_rate: number;
  avg_risk_score: number;
  decisions_per_minute: number;
  top_blocked_ips: { ip: string; count: number }[];
  decision_timeline: { ts: string; ALLOW: number; MONITOR: number; BLOCK: number }[];
}

export interface MlMetrics {
  trained: boolean;
  samples?: number;
  test_samples?: number;
  accuracy?: number;
  precision?: number;
  recall?: number;
  f1?: number;
  roc_auc?: number;
  pr_auc?: number;
  brier?: number;
  default_threshold?: number;
  optimal_threshold?: number;
  metrics_at_default_threshold?: ThresholdMetrics;
  metrics_at_optimal_threshold?: ThresholdMetrics;
  confusion_matrix?: number[][];
  feature_importance?: { feature: string; importance: number; std?: number }[];
  roc_curve?: { fpr: number; tpr: number }[];
  pr_curve?: { recall: number; precision: number }[];
  calibration_curve?: { predicted: number; observed: number }[];
  model_comparison?: ModelComparisonRow[];
  chosen_model?: {
    name: string;
    best_params: Record<string, unknown>;
    calibration: string;
  };
  metadata?: ModelMetadata;
  model?: string;
  features?: string[];
}

export interface ThresholdMetrics {
  accuracy: number;
  precision: number;
  recall: number;
  f1: number;
  roc_auc: number;
  pr_auc: number;
  brier: number;
}

export interface ModelComparisonRow {
  name: string;
  cv_f1_mean: number;
  cv_f1_std: number;
  cv_roc_auc: number;
  cv_pr_auc: number;
}

export interface ModelMetadata {
  trained_at: string;
  elapsed_seconds: number;
  dataset_hash: string;
  samples: number;
  test_samples: number;
  attack_rate: number;
  sklearn_version: string;
  python_version: string;
  seed: number;
  cv_folds: number;
}

export interface HealthStatus {
  ok: boolean;
  service: string;
  active_sessions: number;
  ml: {
    trained: boolean;
    model?: string;
    accuracy?: number;
  };
}

export interface Scenario {
  key: string;
  label: string;
  description: string;
}

async function getJSON<T>(path: string): Promise<T> {
  const r = await fetch(`${BASE}${path}`);
  if (!r.ok) throw new Error(`${path}: ${r.status}`);
  return r.json();
}

async function postJSON<T>(path: string, body?: unknown): Promise<T> {
  const r = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!r.ok) throw new Error(`${path}: ${r.status}`);
  return r.json();
}

export const api = {
  health: () => getJSON<HealthStatus>("/health"),
  snapshot: () => getJSON<Snapshot>("/analytics/snapshot"),
  mlMetrics: () => getJSON<MlMetrics>("/analytics/ml"),
  recentEvents: (limit = 100) => getJSON<EventView[]>(`/analytics/events?limit=${limit}`),
  sessions: (activeOnly = false) =>
    getJSON<SessionView[]>(`/sessions?active_only=${activeOnly}`),
  revoke: (session_id: string, reason = "manual revocation") =>
    postJSON<{ ok: boolean }>("/sessions/revoke", { session_id, reason }),
  scenarios: () => getJSON<Scenario[]>("/lab/scenarios"),
  runScenario: (key: string) => postJSON<{ ok: boolean; result: unknown }>(`/lab/run/${key}`),
};

export function eventsWebSocketUrl(): string {
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  return `${proto}://${window.location.host}/api/ws/events`;
}
