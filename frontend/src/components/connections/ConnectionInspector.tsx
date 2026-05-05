import type { TcpTrackedSession } from "../../types/sessions/TcpSession";
import {
  formatEndpoint,
  TCP_SESSION_STATE_LABELS,
} from "./connectionsUtils";

type ConnectionInspectorProps = {
  session: TcpTrackedSession | null;
  selectedIndex: number | null;
};

export default function ConnectionInspector({
  session,
  selectedIndex,
}: ConnectionInspectorProps) {
  return (
    <aside className="connections-panel connections-inspector-panel">
      <div className="connections-panel-head">
        <div>
          <h2>Session Inspector</h2>
          <p>
            {session && selectedIndex !== null
              ? `Session #${String(selectedIndex + 1).padStart(2, "0")}`
              : "No session selected"}
          </p>
        </div>
      </div>

      <div className="connections-inspector-body">
        <div className="connections-endpoint-stack">
          <div className="connections-endpoint-box">
            <span>Endpoint A</span>
            <strong>{session ? formatEndpoint(session, "A") : "-"}</strong>
          </div>
          <div className="connections-direction-mark">-&gt;</div>
          <div className="connections-endpoint-box">
            <span>Endpoint B</span>
            <strong>{session ? formatEndpoint(session, "B") : "-"}</strong>
          </div>
        </div>

        <div className="connections-detail-grid">
          <div className="connections-detail-item">
            <span>State</span>
            <strong>
              {session ? TCP_SESSION_STATE_LABELS[session.state] : "-"}
            </strong>
          </div>
          <div className="connections-detail-item">
            <span>Endpoint A Port</span>
            <strong>{session ? session.endpointA.port : "-"}</strong>
          </div>
          <div className="connections-detail-item">
            <span>Endpoint B Port</span>
            <strong>{session ? session.endpointB.port : "-"}</strong>
          </div>
          <div className="connections-detail-item">
            <span>API Method</span>
            <strong>GET</strong>
          </div>
        </div>

        <div className="connections-payload-box">
          <div className="connections-trace-head">
            <span>Response Item</span>
            <strong>/tcp-sessions</strong>
          </div>
          <pre>{session ? JSON.stringify(session, null, 2) : "{}"}</pre>
        </div>
      </div>
    </aside>
  );
}
