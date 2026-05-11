import { useEffect, useMemo, useState } from "react";
import type { FirewallEvent } from "../../types/firewall/FirewallEvent";
import MetricsAlertsPanel from "./MetricsAlertsPanel";
import MetricsFooter from "./MetricsFooter";
import MetricsLogsPanel from "./MetricsLogsPanel";
import MetricsPageHeader from "./MetricsPageHeader";
import MetricsPanel from "./MetricsPanel";
import MetricsStatusBar from "./MetricsStatusBar";
import MetricsTabs from "./MetricsTabs";
import type { DecisionMix, MetricsStats, MetricsTabKey } from "./metricsTypes";
import {
  alertTone,
  eventMessage,
  firewallAlertId,
  formatEndpoint,
  metricSeries,
  parseTime,
} from "./metricsUtils";
import { useRealtimeObservability } from "./useRealtimeObservability";
import "./Metrics.css";

function getStats(
  alerts: FirewallEvent[],
  events: FirewallEvent[],
  now: number,
): MetricsStats {
  const minuteAgo = now - 60_000;
  const eventsPerMinute = events.filter(
    (event) => parseTime(event.timestamp) >= minuteAgo,
  ).length;
  const blocked = events.filter(
    (event) => event.decision === "block" || event.decision === "error",
  ).length;

  return { alerting: alerts.length, blocked, eventsPerMinute };
}

function getDecisionMix(events: FirewallEvent[]): DecisionMix {
  const allow = events.filter(
    (event) => event.decision === "decrypt" || event.decision === "observe",
  ).length;
  const alert = events.filter(
    (event) => event.decision === "alert" || event.decision === "bypass",
  ).length;
  const block = events.filter(
    (event) => event.decision === "block" || event.decision === "error",
  ).length;
  const total = allow + alert + block || 1;

  return {
    alert: Math.round((alert / total) * 100),
    allow: Math.round((allow / total) * 100),
    block: Math.round((block / total) * 100),
  };
}

function filterEvents(
  events: FirewallEvent[],
  logFilter: string,
): FirewallEvent[] {
  const query = logFilter.trim().toLowerCase();
  if (!query) return events;

  return events.filter((event) =>
    [
      event.source,
      event.decision,
      event.event_type,
      eventMessage(event),
      formatEndpoint(event, "src"),
      formatEndpoint(event, "dst"),
    ]
      .join(" ")
      .toLowerCase()
      .includes(query),
  );
}

export function Metrics() {
  const { alerts, events, isConnected, metrics } = useRealtimeObservability();
  const [activeTab, setActiveTab] = useState<MetricsTabKey>("metrics");
  const [logFilter, setLogFilter] = useState("");
  const [now, setNow] = useState(() => Date.now());
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);

  useEffect(() => {
    const timer = window.setInterval(() => {
      setNow(Date.now());
    }, 1000);

    return () => {
      window.clearInterval(timer);
    };
  }, []);

  const stats = useMemo(
    () => getStats(alerts, events, now),
    [alerts, events, now],
  );
  const decisionMix = useMemo(() => getDecisionMix(events), [events]);
  const selectedAlert = useMemo(
    () =>
      alerts.find((alert) => firewallAlertId(alert) === selectedAlertId) ??
      alerts[0],
    [alerts, selectedAlertId],
  );
  const selectedTone = selectedAlert ? alertTone(selectedAlert) : undefined;
  const trafficValues = useMemo(
    () => metricSeries(metrics, "throughput"),
    [metrics],
  );
  const dropValues = useMemo(
    () => metricSeries(metrics, "drops"),
    [metrics],
  );
  const filteredEvents = useMemo(
    () => filterEvents(events, logFilter),
    [events, logFilter],
  );
  const metricsCount = metrics.length;
  const eventsCount = events.length;
  const filteredEventsCount = filteredEvents.length;
  const trafficSampleCount = trafficValues.length;
  const dropSampleCount = dropValues.length;

  useEffect(() => {
    console.log("[metrics] realtime samples", { total: metricsCount });
  }, [metricsCount]);

  useEffect(() => {
    console.log("[metrics] chart series", {
      drops: dropSampleCount,
      throughput: trafficSampleCount,
    });
  }, [dropSampleCount, trafficSampleCount]);

  useEffect(() => {
    console.log("[metrics] log filter", {
      events: eventsCount,
      filtered: filteredEventsCount,
      query: logFilter,
    });
  }, [eventsCount, filteredEventsCount, logFilter]);

  return (
    <main className="metrics-observability-page">
      <div className="observability-shell">
        <MetricsPageHeader />
        <MetricsStatusBar isConnected={isConnected} stats={stats} />

        <section className="observability-tab-shell observability-panel">
          <MetricsTabs activeTab={activeTab} onTabChange={setActiveTab} />
          <div className="observability-tab-panels">
            {activeTab === "metrics" ? (
              <MetricsPanel
                decisionMix={decisionMix}
                dropValues={dropValues}
                eventsCount={events.length}
                metrics={metrics}
                now={now}
                trafficValues={trafficValues}
              />
            ) : null}

            {activeTab === "alerts" ? (
              <MetricsAlertsPanel
                alerts={alerts}
                now={now}
                onSelectAlert={setSelectedAlertId}
                selectedAlert={selectedAlert}
                selectedTone={selectedTone}
              />
            ) : null}

            {activeTab === "logs" ? (
              <MetricsLogsPanel
                events={filteredEvents}
                logFilter={logFilter}
                onLogFilterChange={setLogFilter}
              />
            ) : null}
          </div>
        </section>

        <MetricsFooter />
      </div>
    </main>
  );
}
