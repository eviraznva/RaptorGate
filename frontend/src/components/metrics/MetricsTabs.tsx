import type { MetricsTabKey } from "./metricsTypes";

const tabs: Array<{ id: MetricsTabKey; index: string; label: string }> = [
  { id: "metrics", index: "01", label: "Metrics" },
  { id: "alerts", index: "02", label: "Alerts" },
  { id: "logs", index: "03", label: "Logs" },
];

type MetricsTabsProps = {
  activeTab: MetricsTabKey;
  onTabChange: (tab: MetricsTabKey) => void;
};

export default function MetricsTabs({
  activeTab,
  onTabChange,
}: MetricsTabsProps) {
  return (
    <div className="observability-tab-rail" role="tablist" aria-label="Observability tabs">
      {tabs.map((tab) => (
        <button
          key={tab.id}
          className={`observability-tab-button ${activeTab === tab.id ? "active" : ""}`}
          type="button"
          role="tab"
          aria-selected={activeTab === tab.id}
          onClick={() => onTabChange(tab.id)}
        >
          <span className="observability-tab-index">{tab.index}</span>
          <span>{tab.label}</span>
        </button>
      ))}
      <div className="observability-tab-meta">
        <span>Window</span>
        <strong>Live session</strong>
      </div>
    </div>
  );
}
