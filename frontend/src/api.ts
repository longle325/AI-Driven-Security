import type { AdvisorResult, Alert, EvidenceFile, LogEvent, MetricsPayload, RuleVsAi, Summary } from "./types";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init
  });
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return response.json() as Promise<T>;
}

export const api = {
  base: API_BASE,
  health: () => request<Record<string, unknown>>("/health"),
  summary: () => request<Summary>("/api/summary"),
  logs: () => request<{ items: LogEvent[]; total: number }>("/api/logs?limit=1500"),
  detected: () => request<{ items: LogEvent[]; total: number }>("/api/detected?limit=1500"),
  alerts: () => request<{ items: Alert[]; total: number }>("/api/alerts?limit=1500"),
  metrics: () => request<MetricsPayload>("/api/metrics"),
  ruleVsAi: () => request<RuleVsAi>("/api/rule-vs-ai"),
  evidence: () => request<{ items: EvidenceFile[]; directory: string }>("/api/evidence"),
  simulate: (scenario = "mixed", count = 500) =>
    request("/api/simulate", {
      method: "POST",
      body: JSON.stringify({ scenario, count, replace: true })
    }),
  train: () => request("/api/train", { method: "POST" }),
  detect: () => request("/api/detect", { method: "POST" }),
  generateAdvisor: () => request("/api/advisor/generate", { method: "POST" }),
  advisor: (alertId: string) => request<AdvisorResult>(`/api/advisor/${alertId}`, { method: "POST" }),
  exportEvidence: () => request("/api/export", { method: "POST" })
};
