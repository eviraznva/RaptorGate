import type {
  TcpTrackedSession,
  TcpTrackedSessionState,
} from "../../types/sessions/TcpSession";
import {
  TCP_SESSION_STATE_LABELS,
  TCP_SESSION_STATES,
} from "./connectionsUtils";

type ConnectionsTableProps = {
  sessions: TcpTrackedSession[];
  selectedIndex: number | null;
  search: string;
  stateFilter: TcpTrackedSessionState | "all";
  onSearchChange: (search: string) => void;
  onStateFilterChange: (state: TcpTrackedSessionState | "all") => void;
  onSelect: (index: number) => void;
  onExport: () => void;
};

export default function ConnectionsTable({
  sessions,
  selectedIndex,
  search,
  stateFilter,
  onSearchChange,
  onStateFilterChange,
  onSelect,
  onExport,
}: ConnectionsTableProps) {
  return (
    <section className="connections-panel connections-table-panel">
      <div className="connections-panel-head connections-table-head">
        <div>
          <h2>Tracked Sessions</h2>
          <p>Endpoint A -&gt; Endpoint B</p>
        </div>
        <div className="connections-filters">
          <label className="connections-search-box">
            <span>?</span>
            <input
              value={search}
              placeholder="Search IP, port, state"
              onChange={(event) => onSearchChange(event.target.value)}
            />
          </label>
          <select
            value={stateFilter}
            aria-label="Filter by state"
            onChange={(event) =>
              onStateFilterChange(
                event.target.value as TcpTrackedSessionState | "all",
              )
            }
          >
            <option value="all">All states</option>
            {TCP_SESSION_STATES.map((state) => (
              <option key={state} value={state}>
                {TCP_SESSION_STATE_LABELS[state]}
              </option>
            ))}
          </select>
          <button
            type="button"
            className="connections-ghost-button"
            onClick={onExport}
          >
            Export
          </button>
        </div>
      </div>

      <div className="connections-table-wrap">
        <table>
          <thead>
            <tr>
              <th>State</th>
              <th>Endpoint A</th>
              <th>Port</th>
              <th>Direction</th>
              <th>Endpoint B</th>
              <th>Port</th>
            </tr>
          </thead>
          <tbody>
            {sessions.map((session, index) => (
              <tr
                key={`${session.endpointA.ip}:${session.endpointA.port}-${session.endpointB.ip}:${session.endpointB.port}-${index}`}
                className={index === selectedIndex ? "is-selected" : ""}
                onClick={() => onSelect(index)}
              >
                <td>
                  <span className={`state-pill state-${session.state}`}>
                    {TCP_SESSION_STATE_LABELS[session.state]}
                  </span>
                </td>
                <td className="endpoint">{session.endpointA.ip}</td>
                <td>{session.endpointA.port}</td>
                <td className="route-mark">----------&gt;</td>
                <td className="endpoint">{session.endpointB.ip}</td>
                <td>{session.endpointB.port}</td>
              </tr>
            ))}
            {sessions.length === 0 ? (
              <tr>
                <td className="connections-empty-row" colSpan={6}>
                  No TCP sessions match current filters
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
    </section>
  );
}
