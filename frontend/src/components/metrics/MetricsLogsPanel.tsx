import type { FirewallEvent } from "../../types/firewall/FirewallEvent";
import {
  decisionClass,
  eventMessage,
  formatEndpoint,
  formatTime,
} from "./metricsUtils";

type MetricsLogsPanelProps = {
  events: FirewallEvent[];
  logFilter: string;
  onLogFilterChange: (value: string) => void;
};

export default function MetricsLogsPanel({
  events,
  logFilter,
  onLogFilterChange,
}: MetricsLogsPanelProps) {
  return (
    <section className="observability-tab-panel" role="tabpanel">
      <div className="logs-toolbar">
        <label>
          <span>Filter</span>
          <input
            type="search"
            value={logFilter}
            placeholder="source, verdict, ip..."
            onChange={(event) => onLogFilterChange(event.target.value)}
          />
        </label>
        <button type="button" onClick={() => onLogFilterChange("block")}>Block</button>
        <button type="button" onClick={() => onLogFilterChange("alert")}>Alert</button>
        <button type="button" onClick={() => onLogFilterChange("")}>All</button>
      </div>

      <div className="log-table panel-inset">
        <div className="log-head">
          <span>Time</span>
          <span>Source</span>
          <span>Decision</span>
          <span>Flow</span>
          <span>Message</span>
        </div>
        <div className="log-body">
          {events.length === 0 ? (
            <div className="empty-state log-empty">Waiting for firewall events</div>
          ) : (
            events.map((event) => (
              <div
                key={`${event.timestamp}:${event.event_type}:${event.src_ip ?? ""}:${event.dst_ip ?? ""}`}
                className="log-row"
              >
                <span>{formatTime(event.timestamp)}</span>
                <span>{event.source}</span>
                <span className={decisionClass(event.decision)}>{event.decision}</span>
                <span>{formatEndpoint(event, "src")} -&gt; {formatEndpoint(event, "dst")}</span>
                <span>{eventMessage(event)}</span>
              </div>
            ))
          )}
        </div>
      </div>
    </section>
  );
}
