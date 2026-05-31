import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  Bot,
  BrainCircuit,
  Database,
  Download,
  Loader2,
  Pause,
  Play,
  RefreshCw,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  StepForward,
  TerminalSquare,
  Zap
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";
import { api } from "./api";
import type { AdvisorResult, Alert, LogEvent, StreamStatus, Summary } from "./types";

const EMPTY_SUMMARY: Summary = {
  total_logs: 0,
  detected_logs: 0,
  total_alerts: 0,
  label_distribution: {},
  severity_distribution: {},
  threat_distribution: {},
  latest_alert_time: null,
  metrics: {},
  llm: { mode: "fallback", provider: "openai", model: "gpt-5.4-mini", has_key: false }
};

const EMPTY_STREAM: StreamStatus = {
  total: 0,
  processed: 0,
  remaining: 0,
  done: true
};

const THREAT_COLORS: Record<string, string> = {
  brute_force: "#ffb020",
  dos_ddos: "#ff5f1f",
  botnet: "#ff3b5f",
  infiltration: "#9b7cff",
  web_attack: "#36c5f0",
  suspicious: "#f97316",
  normal: "#25d07f"
};

function formatPct(value?: number) {
  if (typeof value !== "number" || Number.isNaN(value)) return "n/a";
  return `${Math.round(value * 1000) / 10}%`;
}

function formatNumber(value?: number) {
  return new Intl.NumberFormat().format(value || 0);
}

function severityClass(severity?: string) {
  return `severity severity-${String(severity || "unknown").replaceAll("_", "-").toLowerCase()}`;
}

function predictionClass(value?: string) {
  return `prediction prediction-${String(value || "pending").replaceAll("_", "-").toLowerCase()}`;
}

function isThreat(row: LogEvent) {
  return Boolean(row.ml_prediction && row.ml_prediction !== "normal") || Boolean(row.rule_prediction && row.rule_prediction !== "normal");
}

function isMlThreat(row: LogEvent | Alert) {
  return Boolean(row.ml_prediction && row.ml_prediction !== "normal");
}

function entries(source: Record<string, number>) {
  return Object.entries(source || {})
    .map(([name, value]) => ({ name, value: Number(value) || 0 }))
    .sort((a, b) => b.value - a.value);
}

function eventTimeline(rows: LogEvent[]) {
  const buckets = new Map<string, { time: string; normal: number; threat: number }>();
  for (const row of rows.slice(-180)) {
    const time = row.timestamp ? row.timestamp.slice(11, 16) : "n/a";
    const current = buckets.get(time) || { time, normal: 0, threat: 0 };
    if (isThreat(row)) current.threat += 1;
    else current.normal += 1;
    buckets.set(time, current);
  }
  return Array.from(buckets.values()).slice(-28);
}

function currentRunRows(rows: LogEvent[], stream: StreamStatus) {
  if (!rows.length) return [];
  if (stream.total > 0 && rows.length > stream.total) {
    return rows.slice(-Math.min(stream.processed || stream.total, stream.total));
  }
  return rows;
}

function currentRunAlerts(alerts: Alert[], rows: LogEvent[]) {
  if (!alerts.length) return [];
  const refs = new Set(rows.map((row) => row.evidence_ref).filter(Boolean));
  const scoped = alerts.filter((alert) => refs.has(alert.evidence_ref));
  return scoped.length ? scoped : alerts.slice(-Math.min(alerts.length, rows.length || 7));
}

function actionItems(result: AdvisorResult | null) {
  const rec = result?.recommendation;
  return [
    ...(rec?.immediate_next_steps || []),
    ...(rec?.investigation_steps || []),
    ...(rec?.mitigation_actions || [])
  ].slice(0, 5);
}

function Stat({
  label,
  value,
  icon: Icon,
  tone = "neutral"
}: {
  label: string;
  value: string;
  icon: LucideIcon;
  tone?: "neutral" | "good" | "warn" | "bad";
}) {
  return (
    <div className={`stat stat-${tone}`}>
      <Icon size={18} />
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function Panel({
  title,
  children,
  action
}: {
  title: string;
  children: React.ReactNode;
  action?: React.ReactNode;
}) {
  return (
    <section className="panel">
      <header className="panel-head">
        <div>
          <h2>{title}</h2>
        </div>
        {action}
      </header>
      {children}
    </section>
  );
}

function ThreatBars({ data }: { data: Array<{ name: string; value: number }> }) {
  const max = Math.max(1, ...data.map((item) => item.value));
  if (!data.length) return <div className="empty">No threats yet</div>;
  return (
    <div className="threat-bars">
      {data.slice(0, 6).map((item) => (
        <div className="threat-row" key={item.name}>
          <span>{item.name}</span>
          <div>
            <i style={{ width: `${Math.max(5, (item.value / max) * 100)}%`, backgroundColor: THREAT_COLORS[item.name] || "#36c5f0" }} />
          </div>
          <strong>{item.value}</strong>
        </div>
      ))}
    </div>
  );
}

function App() {
  const [summary, setSummary] = useState<Summary>(EMPTY_SUMMARY);
  const [detected, setDetected] = useState<LogEvent[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [stream, setStream] = useState<StreamStatus>(EMPTY_STREAM);
  const [selectedRef, setSelectedRef] = useState<string | null>(null);
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [insight, setInsight] = useState<AdvisorResult | null>(null);
  const [autoStream, setAutoStream] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [insightBusy, setInsightBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const runDetected = useMemo(() => currentRunRows(detected, stream), [detected, stream]);
  const runAlerts = useMemo(() => currentRunAlerts(alerts, runDetected), [alerts, runDetected]);
  const runThreatDistribution = useMemo(
    () =>
      runAlerts.reduce<Record<string, number>>((acc, alert) => {
        const threat = alert.threat_type || "unknown";
        acc[threat] = (acc[threat] || 0) + 1;
        return acc;
      }, {}),
    [runAlerts]
  );
  const latestThreat = useMemo(() => [...runDetected].reverse().find(isThreat) || runDetected[runDetected.length - 1], [runDetected]);
  const selectedEvent = useMemo(
    () => runDetected.find((row) => row.evidence_ref === selectedRef) || latestThreat || null,
    [runDetected, latestThreat, selectedRef]
  );
  const selectedAlert = useMemo(
    () =>
      runAlerts.find((alert) => alert.evidence_ref === selectedEvent?.evidence_ref) ||
      runAlerts.find((alert) => alert.alert_id === selectedAlertId) ||
      runAlerts[runAlerts.length - 1] ||
      null,
    [runAlerts, selectedAlertId, selectedEvent?.evidence_ref]
  );
  const focusEvent = selectedEvent || runDetected.find((row) => row.evidence_ref === selectedAlert?.evidence_ref) || latestThreat || null;
  const threatData = useMemo(() => entries(runThreatDistribution), [runThreatDistribution]);
  const timeline = useMemo(() => eventTimeline(runDetected), [runDetected]);
  const threatRate = runDetected.length ? runAlerts.length / runDetected.length : 0;
  const progress = stream.total ? Math.min(100, (stream.processed / stream.total) * 100) : 0;

  async function loadAll() {
    setError(null);
    try {
      const [summaryData, detectedData, alertsData, streamData] = await Promise.all([
        api.summary(),
        api.detected(),
        api.alerts(),
        api.streamStatus()
      ]);
      setSummary(summaryData);
      setDetected(detectedData.items);
      setAlerts(alertsData.items);
      setStream(streamData);
      const scopedRows = currentRunRows(detectedData.items, streamData);
      const scopedRefs = new Set(scopedRows.map((row) => row.evidence_ref).filter(Boolean));
      const scopedAlerts = alertsData.items.filter((alert) => scopedRefs.has(alert.evidence_ref));
      const newestAlert = alertsData.items[alertsData.items.length - 1];
      const newestAiAlert = [...scopedAlerts].reverse().find(isMlThreat);
      const newestScopedAlert = newestAiAlert || scopedAlerts[scopedAlerts.length - 1] || newestAlert;
      const newestMlThreat = [...scopedRows].reverse().find(isMlThreat);
      const newestThreat = newestMlThreat || [...scopedRows].reverse().find(isThreat);
      if (!selectedRef) setSelectedRef(newestScopedAlert?.evidence_ref || newestThreat?.evidence_ref || null);
      if (!selectedAlertId && newestScopedAlert) setSelectedAlertId(newestScopedAlert.alert_id);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Backend unavailable");
    }
  }

  useEffect(() => {
    void loadAll();
  }, []);

  useEffect(() => {
    setInsight(null);
  }, [selectedAlert?.alert_id]);

  async function runAction(label: string, action: () => Promise<unknown>, reload = true) {
    setBusy(label);
    setError(null);
    try {
      await action();
      if (reload) await loadAll();
    } catch (err) {
      setError(err instanceof Error ? err.message : `${label} failed`);
      setAutoStream(false);
    } finally {
      setBusy(null);
    }
  }

  async function resetScenario() {
    setSelectedRef(null);
    setSelectedAlertId(null);
    setInsight(null);
    setAutoStream(false);
    await runAction("reset", () => api.streamReset("mixed", 120));
  }

  async function stepStream(reload = true) {
    setBusy("stream");
    setError(null);
    try {
      const response = await api.streamStep();
      const details = response.details;
      setStream({ total: details.total, processed: details.processed, remaining: details.remaining, done: details.done });
      if (details.detected?.evidence_ref) setSelectedRef(details.detected.evidence_ref);
      if (details.alert?.alert_id) setSelectedAlertId(details.alert.alert_id);
      if (reload) await loadAll();
      if (details.done) setAutoStream(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : "stream failed");
      setAutoStream(false);
    } finally {
      setBusy(null);
    }
  }

  async function runDemo() {
    await runAction("demo", async () => {
      await api.streamReset("mixed", 120);
      for (let index = 0; index < 30; index += 1) await api.streamStep();
      await api.generateAdvisor();
      await api.exportEvidence();
    });
  }

  async function generateInsight() {
    if (!selectedAlert) return;
    setInsightBusy(true);
    setError(null);
    try {
      setInsight(await api.advisor(selectedAlert.alert_id));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Insight failed");
    } finally {
      setInsightBusy(false);
    }
  }

  useEffect(() => {
    if (!autoStream) return;
    const timer = window.setInterval(() => {
      void stepStream(true);
    }, 850);
    return () => window.clearInterval(timer);
  }, [autoStream]);

  const recentStream = runDetected.slice(-16).reverse();
  const recentAlerts = runAlerts.slice(-7).reverse();
  const actions = actionItems(insight);

  return (
    <main className="soc-shell">
      <header className="hero-bar">
        <div className="brand-line">
          <div className="brand-orbit">
            <ShieldCheck size={24} />
          </div>
          <div>
            <span>AI-Driven Cyber Defense Lab</span>
            <h1>Live Threat Detection Console</h1>
          </div>
        </div>
        <div className="hero-actions">
          <button onClick={() => void resetScenario()} disabled={!!busy}>
            <RotateCcw size={16} />Reset
          </button>
          <button onClick={() => void stepStream()} disabled={!!busy || stream.done}>
            <StepForward size={16} />Step
          </button>
          <button className={autoStream ? "hot" : ""} onClick={() => setAutoStream((value) => !value)} disabled={!!busy && busy !== "stream"}>
            {autoStream ? <Pause size={16} /> : <Play size={16} />}{autoStream ? "Pause" : "Stream"}
          </button>
          <button className="primary" onClick={() => void runDemo()} disabled={!!busy}>
            {busy === "demo" ? <Loader2 className="spin" size={16} /> : <Sparkles size={16} />}Run demo
          </button>
          <button aria-label="Refresh" className="icon" onClick={() => void loadAll()} disabled={!!busy}>
            <RefreshCw size={17} />
          </button>
        </div>
      </header>

      {error ? <div className="error-strip"><AlertTriangle size={16} />{error}</div> : null}

      <section className="runway">
        <div>
          <span>Scenario progress</span>
          <strong>{formatNumber(stream.processed)} / {formatNumber(stream.total || summary.total_logs)} events</strong>
        </div>
        <div className="runway-track">
          <i style={{ width: `${progress}%` }} />
        </div>
        <div className="runway-meta">
          <span>{stream.done ? "complete" : "active"}</span>
          <span>API {api.base.replace("http://", "")}</span>
        </div>
      </section>

      <section className="stat-grid">
        <Stat label="Logs analyzed" value={formatNumber(runDetected.length)} icon={BrainCircuit} tone="good" />
        <Stat label="Incidents" value={formatNumber(runAlerts.length)} icon={ShieldAlert} tone={runAlerts.length ? "warn" : "neutral"} />
        <Stat label="Threat rate" value={formatPct(threatRate)} icon={Zap} tone="warn" />
      </section>

      <section className="workbench">
        <Panel title="Live Events">
          <div className="event-stream">
            {recentStream.length ? recentStream.map((row, index) => {
              const ref = row.evidence_ref || `${row.timestamp}-${index}`;
              const active = focusEvent?.evidence_ref === row.evidence_ref;
              return (
                <button className={`event-row ${isThreat(row) ? "threat" : "clean"} ${active ? "active" : ""}`} key={ref} onClick={() => row.evidence_ref && setSelectedRef(row.evidence_ref)}>
                  <time>{String(row.timestamp).replace("T", " ").slice(11, 19)}</time>
                  <div>
                    <strong>{row.source_ip}</strong>
                    <span>{row.event_type} · {row.endpoint}</span>
                  </div>
                  <em className={predictionClass(row.ml_prediction)}>{row.ml_prediction || "pending"}</em>
                </button>
              );
            }) : <div className="empty">Run demo or step the stream</div>}
          </div>
        </Panel>

        <Panel
          title="AI Detection Focus"
          action={selectedAlert ? <span className={severityClass(selectedAlert.severity)}>{selectedAlert.severity}</span> : null}
        >
          {focusEvent ? (
            <div className="focus-card">
              <div className="focus-top">
                <div>
                  <span>Predicted label</span>
                  <strong>{focusEvent.ml_prediction || "pending"}</strong>
                </div>
                <div className="confidence-ring">
                  <b>{formatPct(focusEvent.ml_confidence)}</b>
                  <span>confidence</span>
                </div>
              </div>

              <div className="evidence-grid">
                <span><b>{focusEvent.source_ip}</b>source</span>
                <span><b>{focusEvent.endpoint}</b>endpoint</span>
                <span><b>{focusEvent.rule_id || "none"}</b>rule</span>
                <span><b>{focusEvent.rule_prediction || "pending"}</b>rule label</span>
              </div>

              <div className="signal-strip">
                <span><b>{focusEvent.request_count_1m}</b>req/min</span>
                <span><b>{focusEvent.failed_login_count_5m}</b>failed login</span>
                <span><b>{focusEvent.unique_ports_1m}</b>ports</span>
                <span><b>{Number(focusEvent.payload_risk_score || 0).toFixed(2)}</b>payload</span>
                <span><b>{Number(focusEvent.endpoint_risk_score || 0).toFixed(2)}</b>endpoint</span>
              </div>

              <div className="rule-note">
                <TerminalSquare size={15} />
                <span>{focusEvent.rule_reason || "No rule reason for this event"}</span>
              </div>
            </div>
          ) : <div className="empty">No event selected</div>}
        </Panel>

        <Panel
          title="Insight"
          action={<button className="primary mini" onClick={() => void generateInsight()} disabled={!selectedAlert || insightBusy}>{insightBusy ? <Loader2 className="spin" size={15} /> : <Bot size={15} />}Generate</button>}
        >
          <div className="insight-panel">
            {insight?.recommendation ? (
              <div className="recommendation-flow">
                <h3>{insight.recommendation.incident_summary || "Incident insight"}</h3>
                <p>{insight.recommendation.threat_explanation || insight.recommendation.severity_reasoning}</p>
                <ol>
                  {actions.map((item) => <li key={item}>{item}</li>)}
                </ol>
              </div>
            ) : (
              <div className="advisor-placeholder">
                <Bot size={22} />
                <span>Generate insight for the selected incident.</span>
              </div>
            )}
          </div>
        </Panel>
      </section>

      <section className="lower-grid">
        <Panel title="Incident Queue">
          <div className="incident-stack">
            {recentAlerts.length ? recentAlerts.map((alert) => (
              <button className={`incident-row ${selectedAlert?.alert_id === alert.alert_id ? "active" : ""}`} key={alert.alert_id} onClick={() => {
                setSelectedAlertId(alert.alert_id);
                setSelectedRef(alert.evidence_ref);
              }}>
                <span className={severityClass(alert.severity)}>{alert.severity}</span>
                <div>
                  <strong>{alert.threat_type}</strong>
                  <small>{alert.source_ip} · {formatPct(alert.ml_confidence)}</small>
                </div>
              </button>
            )) : <div className="empty small">No incidents yet</div>}
          </div>
        </Panel>

        <Panel title="Detection Timeline">
          <div className="chart-box">
            <ResponsiveContainer>
              <AreaChart data={timeline}>
                <defs>
                  <linearGradient id="threat" x1="0" x2="0" y1="0" y2="1">
                    <stop offset="0%" stopColor="#ff5f1f" stopOpacity={0.5} />
                    <stop offset="100%" stopColor="#ff5f1f" stopOpacity={0.02} />
                  </linearGradient>
                  <linearGradient id="normal" x1="0" x2="0" y1="0" y2="1">
                    <stop offset="0%" stopColor="#25d07f" stopOpacity={0.35} />
                    <stop offset="100%" stopColor="#25d07f" stopOpacity={0.02} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="rgba(148, 163, 184, 0.16)" vertical={false} />
                <XAxis dataKey="time" tickLine={false} axisLine={false} tick={{ fill: "#8ea0b6", fontSize: 11 }} />
                <YAxis tickLine={false} axisLine={false} tick={{ fill: "#8ea0b6", fontSize: 11 }} width={28} />
                <Tooltip contentStyle={{ background: "#111827", border: "1px solid #253249", color: "#e5edf8" }} />
                <Area type="monotone" dataKey="normal" stackId="1" stroke="#25d07f" fill="url(#normal)" strokeWidth={2} />
                <Area type="monotone" dataKey="threat" stackId="1" stroke="#ff5f1f" fill="url(#threat)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Panel>

        <Panel title="Threat Mix">
          <ThreatBars data={threatData} />
          <div className="chart-box short">
            <ResponsiveContainer>
              <BarChart data={threatData.slice(0, 6)} layout="vertical" margin={{ left: 8, right: 20 }}>
                <CartesianGrid stroke="rgba(148, 163, 184, 0.16)" horizontal={false} />
                <XAxis type="number" hide />
                <YAxis dataKey="name" type="category" width={92} tickLine={false} axisLine={false} tick={{ fill: "#8ea0b6", fontSize: 11 }} />
                <Tooltip contentStyle={{ background: "#111827", border: "1px solid #253249", color: "#e5edf8" }} />
                <Bar dataKey="value" fill="#36c5f0" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>
      </section>

      <footer className="meta-footer">
        <span><Database size={14} />{summary.metrics.dataset || "IDS2025"}</span>
        <span><BrainCircuit size={14} />{summary.metrics.model || "RandomForestClassifier"}</span>
        <span><Download size={14} />Evidence export available from backend</span>
      </footer>
    </main>
  );
}

export default App;
