import { useEffect, useState } from "react";
import { io } from "socket.io-client";
import type { FirewallEvent } from "../../types/firewall/FirewallEvent";
import type { RealtimeMetric } from "./metricsTypes";
import { firewallAlertId, isFirewallAlert } from "./metricsUtils";

const MAX_EVENTS = 160;
const MAX_ALERTS = 80;
const MAX_METRICS = 120;

function isRealtimeMetric(value: unknown): value is RealtimeMetric {
  if (!value || typeof value !== "object") return false;
  const metric = value as Partial<RealtimeMetric>;
  return (
    typeof metric.name === "string" &&
    typeof metric.value === "number" &&
    Number.isFinite(metric.value) &&
    typeof metric.unit === "string" &&
    typeof metric.timestamp === "string"
  );
}

function resolveMetricsUrl(): { url: string; path: string } {
  const envUrl = import.meta.env.RAPTOR_GATE_METRICS_WS_URL;
  if (envUrl) {
    const u = new URL(envUrl);
    return { url: `${u.origin}/metrics`, path: `${u.pathname}/socket.io`.replace(/\/+/g, "/") };
  }
  return { url: `${window.location.origin}/metrics`, path: "/metrics/socket.io" };
}

function resolveAlertsUrl(): { url: string; path: string } {
  const envUrl = import.meta.env.RAPTOR_GATE_ALERTS_WS_URL;
  if (envUrl) {
    const u = new URL(envUrl);
    return { url: `${u.origin}/alerts`, path: `${u.pathname}/socket.io`.replace(/\/+/g, "/") };
  }
  return { url: `${window.location.origin}/alerts`, path: "/alerts/socket.io" };
}

export function useRealtimeObservability() {
  const [events, setEvents] = useState<FirewallEvent[]>([]);
  const [alerts, setAlerts] = useState<FirewallEvent[]>([]);
  const [metrics, setMetrics] = useState<RealtimeMetric[]>([]);
  const [metricsConnected, setMetricsConnected] = useState(false);
  const [alertsConnected, setAlertsConnected] = useState(false);

  useEffect(() => {
    const { url, path } = resolveMetricsUrl();
    const metricsSocket = io(url, {
      path,
      withCredentials: true,
      transports: ["websocket"],
    });

    console.log("[metrics-ws] connecting", { path, url });

    metricsSocket.on("connect", () => {
      console.log("[metrics-ws] connected", { id: metricsSocket.id });
      setMetricsConnected(true);
    });
    metricsSocket.on("disconnect", (reason) => {
      console.log("[metrics-ws] disconnected", { reason });
      setMetricsConnected(false);
    });
    metricsSocket.on("connect_error", (error) => {
      console.log("[metrics-ws] connect_error", { message: error.message });
    });
    metricsSocket.on("metrics", (metric: unknown) => {
      if (!isRealtimeMetric(metric)) {
        console.log("[metrics-ws] invalid metric payload", {
          keys: metric && typeof metric === "object" ? Object.keys(metric) : [],
        });
        return;
      }

      console.log("[metrics-ws] metric", {
        name: metric.name,
        timestamp: metric.timestamp,
        unit: metric.unit,
        value: metric.value,
      });
      setMetrics((current) => [metric, ...current].slice(0, MAX_METRICS));
    });

    return () => {
      metricsSocket.disconnect();
    };
  }, []);

  useEffect(() => {
    const { url, path } = resolveAlertsUrl();
    const alertsSocket = io(url, {
      path,
      withCredentials: true,
      transports: ["websocket"],
    });

    console.log("[alerts-ws] connecting", { path, url });

    alertsSocket.on("connect", () => {
      console.log("[alerts-ws] connected", { id: alertsSocket.id });
      setAlertsConnected(true);
    });
    alertsSocket.on("disconnect", (reason) => {
      console.log("[alerts-ws] disconnected", { reason });
      setAlertsConnected(false);
    });
    alertsSocket.on("connect_error", (error) => {
      console.log("[alerts-ws] connect_error", { message: error.message });
    });
    alertsSocket.on("firewall-events", (event: FirewallEvent) => {
      console.log("[alerts-ws] firewall event", {
        decision: event.decision,
        eventType: event.event_type,
        timestamp: event.timestamp,
      });
      setEvents((current) => [event, ...current].slice(0, MAX_EVENTS));
      if (isFirewallAlert(event)) {
        setAlerts((current) =>
          [
            event,
            ...current.filter((item) => firewallAlertId(item) !== firewallAlertId(event)),
          ].slice(0, MAX_ALERTS),
        );
      }
    });

    return () => {
      alertsSocket.disconnect();
    };
  }, []);

  return { alerts, events, isConnected: metricsConnected && alertsConnected, metrics };
}
