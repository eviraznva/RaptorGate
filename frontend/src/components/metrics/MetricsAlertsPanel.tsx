import type { FirewallEvent } from "../../types/firewall/FirewallEvent";
import type { AlertTone } from "./metricsTypes";
import {
  alertDetails,
  alertSeverity,
  alertTone,
  alertTitle,
  alertStyle,
  firewallAlertId,
  formatAge,
  formatTime,
} from "./metricsUtils";

type MetricsAlertsPanelProps = {
  alerts: FirewallEvent[];
  now: number;
  onSelectAlert: (id: string) => void;
  selectedAlert: FirewallEvent | undefined;
  selectedTone: AlertTone | undefined;
};

export default function MetricsAlertsPanel({
  alerts,
  now,
  onSelectAlert,
  selectedAlert,
  selectedTone,
}: MetricsAlertsPanelProps) {
  const selectedDetails = selectedAlert && selectedTone
    ? alertDetails(selectedAlert, selectedTone)
    : [];

  return (
    <section className="observability-tab-panel" role="tabpanel">
      <div className="alerts-layout">
        <article className="alert-focus panel-inset">
          <div className="observability-panel-head">
            <div>
              <h2>Realtime alert queue</h2>
              <p>Alerts received from Socket.IO /realtime</p>
            </div>
            <span className="observability-panel-code status-danger">{alerts.length} open</span>
          </div>
          <div className="alert-list">
            {alerts.length === 0 ? (
              <div className="empty-state">Waiting for alerts on /realtime</div>
            ) : (
              alerts.map((alert) => {
                const tone = alertTone(alert);
                const id = firewallAlertId(alert);

                return (
                  <button
                    key={id}
                    className={`alert-row ${selectedAlert && firewallAlertId(selectedAlert) === id ? "active" : ""}`}
                    type="button"
                    style={alertStyle(tone)}
                    onClick={() => onSelectAlert(id)}
                  >
                    <span className={`alert-severity ${tone.className}`}>
                      {alertSeverity(alert)}
                    </span>
                    <strong>{alertTitle(alert)}</strong>
                    <span>{tone.label} / {alert.event_type.replaceAll("_", " ")}</span>
                    <em>{formatAge(alert.timestamp, now)}</em>
                  </button>
                );
              })
            )}
          </div>
        </article>

        <article className="alert-detail panel-inset">
          {selectedAlert && selectedTone ? (
            <>
              <div className="detail-topline">
                <span className={`alert-severity ${selectedTone.className}`}>
                  {alertSeverity(selectedAlert)}
                </span>
                <span>{selectedTone.label}</span>
              </div>
              <h2>{alertTitle(selectedAlert)}</h2>
              <dl className="detail-grid alert-detail-grid">
                <div>
                  <dt>Created</dt>
                  <dd>{formatTime(selectedAlert.timestamp)}</dd>
                </div>
                {selectedDetails.map((detail) => (
                  <div key={detail.label}>
                    <dt>{detail.label}</dt>
                    <dd style={detail.tone ? { color: detail.tone } : undefined}>
                      {detail.value}
                    </dd>
                  </div>
                ))}
              </dl>
              <div className="alert-palette-note">
                <span style={{ color: selectedTone.color }}>{selectedTone.label}</span>
                <span>
                  {alertSeverity(selectedAlert) === "critical"
                    ? "Immediate operator review"
                    : "Investigate proto event fields"}
                </span>
              </div>
            </>
          ) : (
            <div className="empty-state detail-empty">No alert selected</div>
          )}
        </article>
      </div>
    </section>
  );
}
