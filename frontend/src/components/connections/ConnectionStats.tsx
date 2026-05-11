import type { TcpTrackedSession } from "../../types/sessions/TcpSession";
import {
  countByState,
  formatBytes,
  getEstablishedRatio,
  getTotalSessionBytes,
  getTotalSessionPackets,
} from "./connectionsUtils";

type ConnectionStatsProps = {
  sessions: TcpTrackedSession[];
  isFetching: boolean;
  onRefresh: () => void;
};

export default function ConnectionStats({
  sessions,
  isFetching,
  onRefresh,
}: ConnectionStatsProps) {
  const establishedCount = countByState(sessions, "established");

  return (
    <section className="connections-session-stats-panel connections-panel">
      <div className="connections-panel-head">
        <div>
          <h2>Session Statistics</h2>
          <p>Live TCP tracker distribution and pressure</p>
        </div>
        <div className="connections-head-actions">
          <button
            type="button"
            className="connections-ghost-button"
            onClick={onRefresh}
            disabled={isFetching}
          >
            {isFetching ? "Refreshing" : "Refresh"}
          </button>
        </div>
      </div>

      <div className="connections-stats-grid">
        <article className="connections-stat-card primary">
          <span className="stat-label">Tracked Sessions</span>
          <strong>{sessions.length}</strong>
          <small>active entries returned by gRPC</small>
        </article>
        <article className="connections-stat-card success">
          <span className="stat-label">Established Ratio</span>
          <strong>{getEstablishedRatio(sessions)}%</strong>
          <small>{establishedCount} stable flows</small>
        </article>
        <article className="connections-stat-card cyan">
          <span className="stat-label">Transferred Bytes</span>
          <strong>{formatBytes(getTotalSessionBytes(sessions))}</strong>
          <small>original + reply counters</small>
        </article>
        <article className="connections-stat-card warning">
          <span className="stat-label">Packets</span>
          <strong>{getTotalSessionPackets(sessions).toLocaleString()}</strong>
          <small>original + reply packets</small>
        </article>
      </div>
    </section>
  );
}
