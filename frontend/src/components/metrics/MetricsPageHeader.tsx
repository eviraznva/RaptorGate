export default function MetricsPageHeader() {
  return (
    <header className="observability-header">
      <div className="observability-brand">RaptorGate</div>
      <div className="observability-title-row">
        <span className="observability-title-line" />
        <h1>Operations Observatory</h1>
        <span className="observability-title-line observability-title-line-right" />
      </div>
      <p>Live firewall telemetry, alert triage, and event logs</p>
    </header>
  );
}
