import type { MetricsStats } from "./metricsTypes";

type MetricsStatusBarProps = {
  isConnected: boolean;
  stats: MetricsStats;
};

export default function MetricsStatusBar({
  isConnected,
  stats,
}: MetricsStatusBarProps) {
  return (
    <section className="observability-status-bar observability-panel">
      <div className="observability-status-item module">
        <span className={`observability-live-dot ${isConnected ? "" : "offline"}`} />
        <span>{isConnected ? "Realtime stream online" : "Realtime stream offline"}</span>
      </div>
      <span className="observability-separator">|</span>
      <div className="observability-status-item">
        <span>Route</span>
        <strong>/dashboard/metrics</strong>
      </div>
      <span className="observability-separator">|</span>
      <div className="observability-status-item">
        <span>Events/min</span>
        <strong>{stats.eventsPerMinute.toLocaleString()}</strong>
      </div>
      <span className="observability-separator">|</span>
      <div className="observability-status-item">
        <span>Blocked</span>
        <strong className="status-danger">{stats.blocked.toLocaleString()}</strong>
      </div>
      <span className="observability-separator">|</span>
      <div className="observability-status-item">
        <span>Alert queue</span>
        <strong>{stats.alerting.toLocaleString()}</strong>
      </div>
    </section>
  );
}
