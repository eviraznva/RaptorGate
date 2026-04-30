import type { DecisionMix, RealtimeMetric } from "./metricsTypes";
import MetricsCharts from "./MetricsCharts";
import MetricsSummaryCards from "./MetricsSummaryCards";

type MetricsPanelProps = {
  decisionMix: DecisionMix;
  dropValues: number[];
  eventsCount: number;
  metrics: RealtimeMetric[];
  now: number;
  trafficValues: number[];
};

export default function MetricsPanel({
  decisionMix,
  dropValues,
  eventsCount,
  metrics,
  now,
  trafficValues,
}: MetricsPanelProps) {
  return (
    <section className="observability-tab-panel" role="tabpanel">
      <MetricsSummaryCards
        dropValues={dropValues}
        metrics={metrics}
        now={now}
        trafficValues={trafficValues}
      />
      <MetricsCharts
        decisionMix={decisionMix}
        dropValues={dropValues}
        eventsCount={eventsCount}
        trafficValues={trafficValues}
      />
    </section>
  );
}
