import type { TcpTrackedSession } from "../../types/sessions/TcpSession";
import { countByState, getClosingCount } from "./connectionsUtils";

type ConnectionsStatusBarProps = {
  sessions: TcpTrackedSession[];
  isFetching: boolean;
};

export default function ConnectionsStatusBar({
  sessions,
  isFetching,
}: ConnectionsStatusBarProps) {
  return (
    <section className="connections-status-bar connections-panel">
      <div className="connections-status-item module">
        <span className="connections-live-dot" />
        <span>{isFetching ? "Session Tracker Refreshing" : "Session Tracker Active"}</span>
      </div>
      <span className="connections-separator">|</span>
      <div className="connections-status-item">
        <span className="label">Tracked</span>
        <strong>{sessions.length}</strong>
      </div>
      <span className="connections-separator">|</span>
      <div className="connections-status-item">
        <span className="label">Established</span>
        <strong className="success">{countByState(sessions, "established")}</strong>
      </div>
      <span className="connections-separator">|</span>
      <div className="connections-status-item">
        <span className="label">Closing</span>
        <strong className="warning">{getClosingCount(sessions)}</strong>
      </div>
    </section>
  );
}
