export default function ConnectionsPageHeader() {
  return (
    <header className="connections-page-header">
      <div className="connections-brand">RaptorGate</div>
      <div className="connections-divider">
        <div className="connections-divider-line" />
        <h1>Connections</h1>
        <div className="connections-divider-line right" />
      </div>
      <div className="connections-subtitle">
        TCP Tracked Sessions / FirewallQueryService.GetTcpSessions
      </div>
    </header>
  );
}
