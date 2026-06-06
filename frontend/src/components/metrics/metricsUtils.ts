import type { CSSProperties } from "react";
import type { FirewallEvent } from "../../types/firewall/FirewallEvent";
import type {
  AlertDetailRow,
  AlertTone,
  RealtimeMetric,
} from "./metricsTypes";

const timeFormatter = new Intl.DateTimeFormat(undefined, {
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
});

export function parseTime(value: string): number {
  const timestamp = Date.parse(value);
  return Number.isNaN(timestamp) ? 0 : timestamp;
}

export function formatTime(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "--:--:--" : timeFormatter.format(date);
}

export function formatAge(value: string, now: number): string {
  const timestamp = parseTime(value);
  if (!timestamp) return "now";

  const seconds = Math.max(0, Math.round((now - timestamp) / 1000));
  if (seconds < 60) return `${seconds}s ago`;

  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;

  return `${Math.round(minutes / 60)}h ago`;
}

export function formatEndpoint(event: FirewallEvent, side: "src" | "dst"): string {
  const ip = side === "src" ? event.src_ip : event.dst_ip;
  const port = side === "src" ? event.src_port : event.dst_port;

  if (!ip) return "unknown";
  return port ? `${ip}:${port}` : ip;
}

export function formatMetric(metric: RealtimeMetric | undefined): string {
  if (!metric || !Number.isFinite(metric.value)) return "—";

  const value = metric.value >= 100 ? Math.round(metric.value).toLocaleString() : metric.value.toFixed(1);
  return `${value} ${metric.unit}`;
}

export function eventMessage(event: FirewallEvent): string {
  return (
    event.signature_name ??
    event.reason ??
    event.domain ??
    event.sni ??
    event.category ??
    event.event_type.replaceAll("_", " ")
  );
}

export function decisionClass(decision: FirewallEvent["decision"]): string {
  if (decision === "block" || decision === "error") return "decision-block";
  if (decision === "alert" || decision === "bypass") return "decision-alert";
  if (decision === "decrypt" || decision === "observe") return "decision-observe";
  return "decision-allow";
}

export function isFirewallAlert(event: FirewallEvent): boolean {
  return (
    event.decision === "alert" ||
    event.decision === "block" ||
    event.decision === "error" ||
    event.event_type === "tls_decryption_exclusion_activated"
  );
}

export function firewallAlertId(event: FirewallEvent): string {
  return [
    event.timestamp,
    event.event_type,
    event.signature_id ?? event.log_id ?? event.src_ip ?? event.domain ?? event.sni ?? "",
  ].join(":");
}

export function alertSeverity(event: FirewallEvent): "info" | "warning" | "critical" {
  if (event.decision === "block" || event.decision === "error") {
    return "critical";
  }

  const severity = event.severity?.toLowerCase();
  if (severity === "critical" || severity === "high") {
    return "critical";
  }

  return "warning";
}

export function alertTitle(event: FirewallEvent): string {
  return eventMessage(event);
}

export function inferAlertKind(event: FirewallEvent): string {
  if (event.source === "DNS") return "DNS / ECH";
  if (event.source === "ML") return "ML";
  if (event.source === "IPS") return "IPS";

  if (event.event_type.includes("tls_decryption")) {
    return "TLS DECRYPTION";
  }

  if (event.source === "TLS") return "TLS";

  return event.source;
}

export function alertTone(event: FirewallEvent): AlertTone {
  const kind = inferAlertKind(event);
  const severity = alertSeverity(event);

  if (severity === "critical") {
    return {
      color: "#f43f5e",
      soft: "rgba(244, 63, 94, 0.1)",
      className: "critical",
      label: kind,
    };
  }

  if (severity === "warning") {
    const cyanTone = event.source === "DNS" || event.source === "ML";
    return {
      color: cyanTone ? "#06b6d4" : "#f59e0b",
      soft: cyanTone ? "rgba(6, 182, 212, 0.12)" : "rgba(245, 158, 11, 0.1)",
      className: cyanTone ? "medium" : "high",
      label: kind,
    };
  }

  return {
    color: "#10b981",
    soft: "rgba(16, 185, 129, 0.1)",
    className: "info",
    label: kind,
  };
}

export function alertStyle(tone: AlertTone): CSSProperties {
  return { "--alert-color": tone.color, "--alert-soft": tone.soft } as CSSProperties;
}

function appendDetail(
  rows: AlertDetailRow[],
  label: string,
  value: string | number | boolean | undefined,
  tone?: string,
) {
  if (value === undefined || value === "") return;

  rows.push({ label, value: String(value), tone });
}

export function alertDetails(event: FirewallEvent, tone: AlertTone): AlertDetailRow[] {
  const rows: AlertDetailRow[] = [];

  appendDetail(rows, "Event", event.event_type.replaceAll("_", " "));
  appendDetail(rows, "Decision", event.decision, tone.color);
  appendDetail(rows, "Source", formatEndpoint(event, "src"));
  appendDetail(rows, "Destination", formatEndpoint(event, "dst"));
  appendDetail(rows, "Signature ID", event.signature_id);
  appendDetail(rows, "Signature", event.signature_name);
  appendDetail(rows, "Category", event.category);
  appendDetail(rows, "Severity", event.severity, tone.color);
  appendDetail(rows, "Action", event.action);
  appendDetail(rows, "Transport", event.transport_protocol);
  appendDetail(rows, "Application", event.app_protocol);
  appendDetail(rows, "Interface", event.interface);
  appendDetail(rows, "Payload", event.payload_length ? `${event.payload_length} bytes` : undefined);
  appendDetail(rows, "SNI", event.sni);
  appendDetail(rows, "Domain", event.domain);
  appendDetail(rows, "TLS", event.tls_version);
  appendDetail(rows, "Stage", event.stage);
  appendDetail(rows, "Reason", event.reason);
  appendDetail(rows, "Mode", event.mode);
  appendDetail(rows, "Direction", event.direction);
  appendDetail(rows, "Blocked", event.blocked);
  appendDetail(rows, "Log ID", event.log_id);
  appendDetail(rows, "ECH origin", event.ech_origin);
  appendDetail(rows, "ECH action", event.ech_action);
  appendDetail(rows, "ML score", event.ml_score);
  appendDetail(rows, "ML threshold", event.ml_threshold);
  appendDetail(rows, "Model checksum", event.model_checksum);
  appendDetail(rows, "Attack type", event.attack_type);

  return rows;
}

export function metricSeries(
  metrics: RealtimeMetric[],
  name: string,
): number[] {
  return metrics
    .filter((metric) => metric.name === name && Number.isFinite(metric.value))
    .slice(0, 18)
    .reverse()
    .map((metric) => metric.value);
}

export function latestMetric(
  metrics: RealtimeMetric[],
  name: string,
): RealtimeMetric | undefined {
  return metrics.find((metric) => metric.name === name);
}
