import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Bot,
  BrainCircuit,
  CheckCircle2,
  Database,
  Download,
  FileArchive,
  Filter,
  Gauge,
  GitCompareArrows,
  ListFilter,
  Loader2,
  Play,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  TerminalSquare
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";
import { api } from "./api";
import type { AdvisorResult, Alert, EvidenceFile, LogEvent, MetricsPayload, RuleVsAi, Summary } from "./types";

type ViewId = "overview" | "logs" | "alerts" | "advisor" | "metrics" | "compare" | "evidence";

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

const EMPTY_METRICS: MetricsPayload = {
  metrics: {},
  classification_report: "",
  feature_importance: []
};

const EMPTY_RULE_AI: RuleVsAi = {
  total: 0,
  agreement: 0,
  disagreement: 0,
  agreement_rate: 0,
  rule_counts: {},
  ml_counts: {},
  examples: []
};

const NAV_ITEMS: Array<{ id: ViewId; label: string; icon: LucideIcon }> = [
  { id: "overview", label: "Overview", icon: Gauge },
  { id: "logs", label: "Live Logs", icon: Database },
  { id: "alerts", label: "Threat Alerts", icon: ShieldAlert },
  { id: "advisor", label: "LLM Advisor", icon: Bot },
  { id: "metrics", label: "Model Metrics", icon: BarChart3 },
  { id: "compare", label: "Rule vs AI", icon: GitCompareArrows },
  { id: "evidence", label: "Evidence", icon: FileArchive }
];

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#b42318",
  high: "#c2410c",
  medium: "#c47b19",
  low: "#177e89",
  informational: "#647067",
  unknown: "#7c7468"
};

const THREAT_COLORS = ["#b42318", "#c47b19", "#177e89", "#29443b", "#5e6c5b", "#8b5e34"];

function entries(source: Record<string, number>) {
  return Object.entries(source || {})
    .map(([name, value]) => ({ name, value: Number(value) || 0 }))
    .sort((a, b) => b.value - a.value);
}

function formatPct(value?: number) {
  if (typeof value !== "number" || Number.isNaN(value)) return "n/a";
  return `${Math.round(value * 1000) / 10}%`;
}

function formatNumber(value?: number) {
  return new Intl.NumberFormat().format(value || 0);
}

function classForSeverity(severity: string) {
  return `severity severity-${severity.toLowerCase()}`;
}

function timeline(logs: LogEvent[]) {
  const buckets = new Map<string, number>();
  for (const log of logs) {
    const key = log.timestamp ? log.timestamp.slice(11, 16) : "n/a";
    buckets.set(key, (buckets.get(key) || 0) + 1);
  }
  return Array.from(buckets.entries())
    .map(([time, events]) => ({ time, events }))
    .slice(-36);
}

function listFromRecommendation(value: string[] | undefined) {
  return Array.isArray(value) ? value : [];
}

function MetricTile({
  label,
  value,
  icon: Icon,
  tone = "neutral"
}: {
  label: string;
  value: string;
  icon: LucideIcon;
  tone?: "neutral" | "danger" | "warn" | "good";
}) {
  return (
    <section className={`metric-tile metric-${tone}`}>
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
      </div>
      <Icon size={22} strokeWidth={1.8} />
    </section>
  );
}

function Panel({
  title,
  icon: Icon,
  children,
  action
}: {
  title: string;
  icon?: LucideIcon;
  children: React.ReactNode;
  action?: React.ReactNode;
}) {
  return (
    <section className="panel">
      <div className="panel-title">
        <div className="panel-heading">{Icon ? <Icon size={18} /> : null}<span>{title}</span></div>
        {action}
      </div>
      {children}
    </section>
  );
}

function DistributionList({ data, colorMap }: { data: Array<{ name: string; value: number }>; colorMap?: Record<string, string> }) {
  const total = data.reduce((sum, item) => sum + item.value, 0);
  if (!data.length) return <div className="empty-state">No data available</div>;
  return (
    <div className="distribution">
      {data.map((item, index) => {
        const width = total ? `${Math.max(4, (item.value / total) * 100)}%` : "0%";
        const color = colorMap?.[item.name] || THREAT_COLORS[index % THREAT_COLORS.length];
        return (
          <div className="dist-row" key={item.name}>
            <span>{item.name}</span>
            <div className="dist-track"><i style={{ width, backgroundColor: color }} /></div>
            <strong>{item.value}</strong>
          </div>
        );
      })}
    </div>
  );
}

function DataTable({
  rows,
  columns,
  getClassName
}: {
  rows: Array<Record<string, unknown>>;
  columns: Array<{ key: string; label: string; render?: (row: Record<string, unknown>) => React.ReactNode }>;
  getClassName?: (row: Record<string, unknown>) => string;
}) {
  if (!rows.length) return <div className="empty-state">No rows</div>;
  return (
    <div className="table-shell">
      <table>
        <thead>
          <tr>{columns.map((column) => <th key={column.key}>{column.label}</th>)}</tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr className={getClassName?.(row)} key={`${String(row.alert_id || row.timestamp || index)}-${index}`}>
              {columns.map((column) => (
                <td key={column.key}>{column.render ? column.render(row) : String(row[column.key] ?? "")}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Overview({ summary, logs, alerts }: { summary: Summary; logs: LogEvent[]; alerts: Alert[] }) {
  const severity = entries(summary.severity_distribution);
  const threats = entries(summary.threat_distribution);
  const timeData = timeline(logs);
  const critical = summary.severity_distribution.critical || 0;
  const high = summary.severity_distribution.high || 0;

  return (
    <div className="view-grid">
      <div className="metric-grid">
        <MetricTile label="Logs processed" value={formatNumber(summary.total_logs)} icon={Database} />
        <MetricTile label="Alerts" value={formatNumber(summary.total_alerts)} icon={ShieldAlert} tone={critical ? "danger" : "warn"} />
        <MetricTile label="High/Critical" value={formatNumber(high + critical)} icon={AlertTriangle} tone={high + critical ? "danger" : "good"} />
        <MetricTile label="Model F1" value={formatPct(summary.metrics.f1_score)} icon={BrainCircuit} tone="good" />
      </div>

      <div className="overview-main">
        <Panel title="Operations Timeline" icon={Activity}>
          <div className="chart tall">
            <ResponsiveContainer>
              <AreaChart data={timeData}>
                <defs>
                  <linearGradient id="eventFill" x1="0" x2="0" y1="0" y2="1">
                    <stop offset="5%" stopColor="#177e89" stopOpacity={0.38} />
                    <stop offset="95%" stopColor="#177e89" stopOpacity={0.02} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="#e7dfd2" vertical={false} />
                <XAxis dataKey="time" tickLine={false} axisLine={false} minTickGap={20} />
                <YAxis tickLine={false} axisLine={false} width={34} />
                <Tooltip />
                <Area type="monotone" dataKey="events" stroke="#177e89" strokeWidth={2} fill="url(#eventFill)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Panel>

        <Panel title="Severity Load" icon={SlidersHorizontal}>
          <DistributionList data={severity} colorMap={SEVERITY_COLORS} />
          <div className="chart compact">
            <ResponsiveContainer>
              <PieChart>
                <Pie data={severity} dataKey="value" nameKey="name" innerRadius={52} outerRadius={82} paddingAngle={2}>
                  {severity.map((item, index) => <Cell key={item.name} fill={SEVERITY_COLORS[item.name] || THREAT_COLORS[index]} />)}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </Panel>
      </div>

      <div className="two-col">
        <Panel title="Threat Mix" icon={ListFilter}>
          <DistributionList data={threats} />
        </Panel>
        <Panel title="Latest Alerts" icon={ShieldCheck}>
          <DataTable
            rows={alerts.slice(0, 7) as unknown as Array<Record<string, unknown>>}
            columns={[
              { key: "alert_id", label: "ID" },
              { key: "severity", label: "Severity", render: (row) => <span className={classForSeverity(String(row.severity))}>{String(row.severity)}</span> },
              { key: "threat_type", label: "Threat" },
              { key: "source_ip", label: "Source" },
              { key: "ml_confidence", label: "ML", render: (row) => formatPct(Number(row.ml_confidence)) }
            ]}
          />
        </Panel>
      </div>
    </div>
  );
}

function LiveLogs({ logs }: { logs: LogEvent[] }) {
  const [label, setLabel] = useState("all");
  const [eventType, setEventType] = useState("all");
  const [query, setQuery] = useState("");
  const labels = ["all", ...Array.from(new Set(logs.map((item) => item.label))).sort()];
  const eventTypes = ["all", ...Array.from(new Set(logs.map((item) => item.event_type))).sort()];
  const filtered = logs.filter((item) => {
    const haystack = `${item.source_ip} ${item.endpoint}`.toLowerCase();
    return (label === "all" || item.label === label)
      && (eventType === "all" || item.event_type === eventType)
      && haystack.includes(query.toLowerCase());
  });

  return (
    <div className="view-grid">
      <Panel title="Log Filters" icon={Filter}>
        <div className="filter-row">
          <label>
            Label
            <select value={label} onChange={(event) => setLabel(event.target.value)}>
              {labels.map((item) => <option key={item}>{item}</option>)}
            </select>
          </label>
          <label>
            Event
            <select value={eventType} onChange={(event) => setEventType(event.target.value)}>
              {eventTypes.map((item) => <option key={item}>{item}</option>)}
            </select>
          </label>
          <label className="search-box">
            Search
            <span><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="source IP or endpoint" /></span>
          </label>
        </div>
      </Panel>
      <Panel title={`Live Log Stream (${filtered.length})`} icon={Database}>
        <DataTable
          rows={filtered.slice(-250).reverse() as unknown as Array<Record<string, unknown>>}
          columns={[
            { key: "timestamp", label: "Time", render: (row) => String(row.timestamp).replace("T", " ").slice(0, 19) },
            { key: "source_ip", label: "Source" },
            { key: "event_type", label: "Event" },
            { key: "endpoint", label: "Endpoint" },
            { key: "status_code", label: "Status" },
            { key: "request_count_1m", label: "Req/m" },
            { key: "failed_login_count_5m", label: "Fails" },
            { key: "unique_ports_1m", label: "Ports" },
            { key: "payload_risk_score", label: "Payload", render: (row) => Number(row.payload_risk_score).toFixed(2) },
            { key: "label", label: "Label" }
          ]}
        />
      </Panel>
    </div>
  );
}

function ThreatAlerts({ alerts, selectedId, onSelect }: { alerts: Alert[]; selectedId: string | null; onSelect: (id: string) => void }) {
  const [severity, setSeverity] = useState("all");
  const [threat, setThreat] = useState("all");
  const [query, setQuery] = useState("");
  const severities = ["all", ...Array.from(new Set(alerts.map((item) => item.severity))).sort()];
  const threats = ["all", ...Array.from(new Set(alerts.map((item) => item.threat_type))).sort()];
  const filtered = alerts.filter((item) => {
    const haystack = `${item.source_ip} ${item.endpoint} ${item.alert_id}`.toLowerCase();
    return (severity === "all" || item.severity === severity)
      && (threat === "all" || item.threat_type === threat)
      && haystack.includes(query.toLowerCase());
  });
  const selected = alerts.find((alert) => alert.alert_id === selectedId) || filtered[0];

  return (
    <div className="split-view">
      <div className="split-main">
        <Panel title="Alert Filters" icon={Filter}>
          <div className="filter-row">
            <label>Severity<select value={severity} onChange={(event) => setSeverity(event.target.value)}>{severities.map((item) => <option key={item}>{item}</option>)}</select></label>
            <label>Threat<select value={threat} onChange={(event) => setThreat(event.target.value)}>{threats.map((item) => <option key={item}>{item}</option>)}</select></label>
            <label className="search-box">Search<span><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="alert, IP, endpoint" /></span></label>
          </div>
        </Panel>
        <Panel title={`Threat Queue (${filtered.length})`} icon={ShieldAlert}>
          <DataTable
            rows={filtered as unknown as Array<Record<string, unknown>>}
            getClassName={(row) => row.alert_id === selected?.alert_id ? "is-selected" : ""}
            columns={[
              { key: "alert_id", label: "ID", render: (row) => <button className="link-button" onClick={() => onSelect(String(row.alert_id))}>{String(row.alert_id)}</button> },
              { key: "severity", label: "Severity", render: (row) => <span className={classForSeverity(String(row.severity))}>{String(row.severity)}</span> },
              { key: "threat_type", label: "Threat" },
              { key: "source_ip", label: "Source" },
              { key: "endpoint", label: "Endpoint" },
              { key: "rule_id", label: "Rule" },
              { key: "ml_confidence", label: "ML", render: (row) => formatPct(Number(row.ml_confidence)) }
            ]}
          />
        </Panel>
      </div>
      <aside className="inspector">
        <Panel title="Alert Inspector" icon={TerminalSquare}>
          {selected ? (
            <div className="inspector-stack">
              <div className="alert-title">
                <span className={classForSeverity(selected.severity)}>{selected.severity}</span>
                <strong>{selected.alert_id}</strong>
              </div>
              <dl>
                <dt>Threat</dt><dd>{selected.threat_type}</dd>
                <dt>Source</dt><dd>{selected.source_ip}</dd>
                <dt>Endpoint</dt><dd>{selected.endpoint}</dd>
                <dt>Rule</dt><dd>{selected.rule_id} · {selected.rule_reason}</dd>
                <dt>ML</dt><dd>{selected.ml_prediction} · {formatPct(selected.ml_confidence)}</dd>
                <dt>Evidence</dt><dd>{selected.evidence_ref}</dd>
              </dl>
              <div className="recommendation">{selected.recommended_action}</div>
            </div>
          ) : <div className="empty-state">No alert selected</div>}
        </Panel>
      </aside>
    </div>
  );
}

function Advisor({ alerts, selectedId, onSelect }: { alerts: Alert[]; selectedId: string | null; onSelect: (id: string) => void }) {
  const selected = alerts.find((alert) => alert.alert_id === selectedId) || alerts[0];
  const [result, setResult] = useState<AdvisorResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setResult(null);
    setError(null);
  }, [selected?.alert_id]);

  async function analyze() {
    if (!selected) return;
    setLoading(true);
    setError(null);
    try {
      const response = await api.advisor(selected.alert_id);
      setResult(response);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Advisor request failed");
    } finally {
      setLoading(false);
    }
  }

  const recommendation = result?.recommendation;
  const groups = [
    ["Immediate Next Steps", listFromRecommendation(recommendation?.immediate_next_steps)],
    ["Investigation Steps", listFromRecommendation(recommendation?.investigation_steps)],
    ["Mitigation Actions", listFromRecommendation(recommendation?.mitigation_actions)],
    ["False Positive Checklist", listFromRecommendation(recommendation?.false_positive_checklist)],
    ["Evidence To Collect", listFromRecommendation(recommendation?.evidence_to_collect)],
    ["Long-Term Improvements", listFromRecommendation(recommendation?.long_term_improvements)]
  ] as const;

  return (
    <div className="split-view advisor-view">
      <div className="split-main">
        <Panel title="Incident Advisor" icon={Bot} action={<button className="primary-button" onClick={analyze} disabled={!selected || loading}>{loading ? <Loader2 className="spin" size={16} /> : <Sparkles size={16} />}Analyze</button>}>
          <div className="advisor-top">
            <label>
              Alert
              <select value={selected?.alert_id || ""} onChange={(event) => onSelect(event.target.value)}>
                {alerts.map((alert) => <option key={alert.alert_id} value={alert.alert_id}>{alert.alert_id} · {alert.threat_type}</option>)}
              </select>
            </label>
            {result ? <span className="mode-chip">{result.mode}{result.model ? ` · ${result.model}` : ""}</span> : null}
          </div>
          {error ? <div className="error-banner">{error}</div> : null}
          <div className="advisory-note">LLM recommendations are advisory only. Human review is required before applying any response action.</div>
          {recommendation ? (
            <div className="advisor-grid">
              <section className="narrative">
                <h3>Incident Summary</h3>
                <p>{recommendation.incident_summary}</p>
                <h3>Threat Explanation</h3>
                <p>{recommendation.threat_explanation}</p>
                <h3>Severity Reasoning</h3>
                <p>{recommendation.severity_reasoning}</p>
                {recommendation.provider_error ? <div className="error-banner">{recommendation.provider_error}</div> : null}
              </section>
              {groups.map(([title, items]) => (
                <section className="list-panel" key={title}>
                  <h3>{title}</h3>
                  <ol>{items.map((item) => <li key={item}>{item}</li>)}</ol>
                </section>
              ))}
            </div>
          ) : (
            <div className="empty-state large">Select an alert and run analysis</div>
          )}
        </Panel>
      </div>
      <aside className="inspector">
        <Panel title="Selected Alert" icon={ShieldAlert}>
          {selected ? (
            <div className="inspector-stack">
              <div className="alert-title"><span className={classForSeverity(selected.severity)}>{selected.severity}</span><strong>{selected.alert_id}</strong></div>
              <dl>
                <dt>Threat</dt><dd>{selected.threat_type}</dd>
                <dt>Source</dt><dd>{selected.source_ip}</dd>
                <dt>Rule</dt><dd>{selected.rule_prediction}</dd>
                <dt>ML Confidence</dt><dd>{formatPct(selected.ml_confidence)}</dd>
              </dl>
            </div>
          ) : <div className="empty-state">No alert</div>}
        </Panel>
      </aside>
    </div>
  );
}

function ModelMetrics({ payload }: { payload: MetricsPayload }) {
  const metrics = payload.metrics || {};
  const importance = payload.feature_importance || [];
  return (
    <div className="view-grid">
      <div className="metric-grid">
        <MetricTile label="Accuracy" value={formatPct(metrics.accuracy)} icon={CheckCircle2} tone="good" />
        <MetricTile label="Precision" value={formatPct(metrics.precision)} icon={Gauge} tone="good" />
        <MetricTile label="Recall" value={formatPct(metrics.recall)} icon={Activity} tone="good" />
        <MetricTile label="F1-score" value={formatPct(metrics.f1_score)} icon={BrainCircuit} tone="good" />
      </div>
      <div className="two-col">
        <Panel title="Feature Importance" icon={BarChart3}>
          <div className="chart tall">
            <ResponsiveContainer>
              <BarChart data={importance} layout="vertical" margin={{ left: 24, right: 20 }}>
                <CartesianGrid stroke="#e7dfd2" horizontal={false} />
                <XAxis type="number" tickLine={false} axisLine={false} />
                <YAxis dataKey="feature" type="category" width={150} tickLine={false} axisLine={false} />
                <Tooltip />
                <Bar dataKey="importance" fill="#c47b19" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>
        <Panel title="Classification Report" icon={TerminalSquare}>
          <pre className="report">{payload.classification_report || "No report yet"}</pre>
        </Panel>
      </div>
    </div>
  );
}

function RuleVsAiView({ ruleVsAi }: { ruleVsAi: RuleVsAi }) {
  const ruleData = entries(ruleVsAi.rule_counts);
  const mlData = entries(ruleVsAi.ml_counts);
  const combined = Array.from(new Set([...ruleData.map((item) => item.name), ...mlData.map((item) => item.name)])).map((name) => ({
    name,
    rule: ruleVsAi.rule_counts[name] || 0,
    ml: ruleVsAi.ml_counts[name] || 0
  }));

  return (
    <div className="view-grid">
      <div className="metric-grid">
        <MetricTile label="Compared" value={formatNumber(ruleVsAi.total)} icon={GitCompareArrows} />
        <MetricTile label="Agreement" value={formatNumber(ruleVsAi.agreement)} icon={ShieldCheck} tone="good" />
        <MetricTile label="Disagreement" value={formatNumber(ruleVsAi.disagreement)} icon={AlertTriangle} tone={ruleVsAi.disagreement ? "warn" : "good"} />
        <MetricTile label="Agreement Rate" value={formatPct(ruleVsAi.agreement_rate)} icon={Gauge} tone="good" />
      </div>
      <Panel title="Detector Comparison" icon={BarChart3}>
        <div className="chart tall">
          <ResponsiveContainer>
            <BarChart data={combined}>
              <CartesianGrid stroke="#e7dfd2" vertical={false} />
              <XAxis dataKey="name" tickLine={false} axisLine={false} />
              <YAxis tickLine={false} axisLine={false} />
              <Tooltip />
              <Legend />
              <Bar dataKey="rule" fill="#29443b" radius={[4, 4, 0, 0]} />
              <Bar dataKey="ml" fill="#c47b19" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </Panel>
      <Panel title="Disagreement Samples" icon={ListFilter}>
        <DataTable
          rows={ruleVsAi.examples as unknown as Array<Record<string, unknown>>}
          columns={[
            { key: "timestamp", label: "Time", render: (row) => String(row.timestamp).replace("T", " ").slice(0, 19) },
            { key: "source_ip", label: "Source" },
            { key: "endpoint", label: "Endpoint" },
            { key: "rule_prediction", label: "Rule" },
            { key: "ml_prediction", label: "ML" },
            { key: "ml_confidence", label: "Confidence", render: (row) => formatPct(Number(row.ml_confidence)) },
            { key: "rule_reason", label: "Reason" }
          ]}
        />
      </Panel>
    </div>
  );
}

function Evidence({ files }: { files: EvidenceFile[] }) {
  return (
    <div className="view-grid">
      <Panel title="Evidence Exports" icon={FileArchive}>
        <DataTable
          rows={files as unknown as Array<Record<string, unknown>>}
          columns={[
            { key: "name", label: "File" },
            { key: "size", label: "Size", render: (row) => `${Math.ceil(Number(row.size) / 1024)} KB` }
          ]}
        />
      </Panel>
      <Panel title="Report Checklist" icon={Download}>
        <div className="checklist">
          {["alerts.csv", "metrics.json", "classification_report.txt", "recommendation_summary.md", "demo_summary.md", "test_case_results.md"].map((name) => (
            <span key={name} className={files.some((file) => file.name === name) ? "present" : "missing"}>
              {files.some((file) => file.name === name) ? <CheckCircle2 size={16} /> : <AlertTriangle size={16} />}
              {name}
            </span>
          ))}
        </div>
      </Panel>
    </div>
  );
}

export default function App() {
  const [view, setView] = useState<ViewId>("overview");
  const [summary, setSummary] = useState<Summary>(EMPTY_SUMMARY);
  const [logs, setLogs] = useState<LogEvent[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [metrics, setMetrics] = useState<MetricsPayload>(EMPTY_METRICS);
  const [ruleVsAi, setRuleVsAi] = useState<RuleVsAi>(EMPTY_RULE_AI);
  const [evidence, setEvidence] = useState<EvidenceFile[]>([]);
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function loadAll() {
    setError(null);
    try {
      const [summaryData, logsData, alertsData, metricsData, compareData, evidenceData] = await Promise.all([
        api.summary(),
        api.logs(),
        api.alerts(),
        api.metrics(),
        api.ruleVsAi(),
        api.evidence()
      ]);
      setSummary(summaryData);
      setLogs(logsData.items);
      setAlerts(alertsData.items);
      setMetrics(metricsData);
      setRuleVsAi(compareData);
      setEvidence(evidenceData.items);
      if (!selectedAlertId && alertsData.items[0]) setSelectedAlertId(alertsData.items[0].alert_id);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load backend data");
    }
  }

  useEffect(() => {
    void loadAll();
  }, []);

  async function runAction(label: string, action: () => Promise<unknown>, reload = true) {
    setBusy(label);
    setError(null);
    try {
      await action();
      if (reload) await loadAll();
    } catch (err) {
      setError(err instanceof Error ? err.message : `${label} failed`);
    } finally {
      setBusy(null);
    }
  }

  async function runDemo() {
    await runAction("demo", async () => {
      await api.simulate("mixed", 700);
      await api.train();
      await api.detect();
      await api.generateAdvisor();
      await api.exportEvidence();
    });
  }

  const pageTitle = useMemo(() => NAV_ITEMS.find((item) => item.id === view)?.label || "Overview", [view]);

  return (
    <div className="app-shell">
      <aside className="side-rail">
        <div className="brand">
          <div className="brand-mark"><ShieldCheck size={25} /></div>
          <div>
            <strong>AI Defense Lab</strong>
            <span>Mini SOC Workbench</span>
          </div>
        </div>
        <nav>
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            return (
              <button className={view === item.id ? "active" : ""} key={item.id} onClick={() => setView(item.id)}>
                <Icon size={18} />
                {item.label}
              </button>
            );
          })}
        </nav>
        <div className="rail-status">
          <span><i />API {api.base.replace("http://", "")}</span>
          <span><i />LLM {summary.llm.mode}</span>
          <span><i className={summary.llm.has_key ? "good-dot" : "warn-dot"} />{summary.llm.model}</span>
        </div>
      </aside>

      <main className="workspace">
        <header className="topbar">
          <div>
            <p>AI-Driven Cyber Defense Lab</p>
            <h1>{pageTitle}</h1>
          </div>
          <div className="command-strip">
            <button onClick={() => void runAction("simulate", () => api.simulate("mixed", 500))} disabled={!!busy}><Play size={16} />Logs</button>
            <button onClick={() => void runAction("train", api.train)} disabled={!!busy}><BrainCircuit size={16} />Train</button>
            <button onClick={() => void runAction("detect", api.detect)} disabled={!!busy}><ShieldAlert size={16} />Detect</button>
            <button onClick={() => void runAction("advisor", api.generateAdvisor)} disabled={!!busy}><Bot size={16} />Advise</button>
            <button onClick={() => void runAction("export", api.exportEvidence)} disabled={!!busy}><Download size={16} />Export</button>
            <button className="primary-button" onClick={() => void runDemo()} disabled={!!busy}>{busy ? <Loader2 className="spin" size={16} /> : <Sparkles size={16} />}Run Demo</button>
            <button className="icon-button" aria-label="Refresh" onClick={() => void loadAll()} disabled={!!busy}><RefreshCw size={17} /></button>
          </div>
        </header>

        {error ? <div className="error-banner">{error}</div> : null}

        <section className="system-strip">
          <span><strong>{formatNumber(summary.total_logs)}</strong> logs</span>
          <span><strong>{formatNumber(summary.total_alerts)}</strong> alerts</span>
          <span><strong>{formatPct(summary.metrics.f1_score)}</strong> F1</span>
          <span><strong>{summary.latest_alert_time ? summary.latest_alert_time.replace("T", " ").slice(0, 19) : "n/a"}</strong> latest</span>
        </section>

        {view === "overview" ? <Overview summary={summary} logs={logs} alerts={alerts} /> : null}
        {view === "logs" ? <LiveLogs logs={logs} /> : null}
        {view === "alerts" ? <ThreatAlerts alerts={alerts} selectedId={selectedAlertId} onSelect={setSelectedAlertId} /> : null}
        {view === "advisor" ? <Advisor alerts={alerts} selectedId={selectedAlertId} onSelect={setSelectedAlertId} /> : null}
        {view === "metrics" ? <ModelMetrics payload={metrics} /> : null}
        {view === "compare" ? <RuleVsAiView ruleVsAi={ruleVsAi} /> : null}
        {view === "evidence" ? <Evidence files={evidence} /> : null}
      </main>
    </div>
  );
}
