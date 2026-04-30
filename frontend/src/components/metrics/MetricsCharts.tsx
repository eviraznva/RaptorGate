import type { DecisionMix } from "./metricsTypes";
import { sparkPath } from "./metricsUtils";

type MetricsChartsProps = {
  decisionMix: DecisionMix;
  eventsCount: number;
  dropValues: number[];
  trafficValues: number[];
};

export default function MetricsCharts({
  decisionMix,
  eventsCount,
  dropValues,
  trafficValues,
}: MetricsChartsProps) {
  return (
    <div className="charts-layout">
      <article className="chart-panel panel-inset wide">
        <div className="observability-panel-head">
          <div>
            <h2>Traffic pressure</h2>
            <p>Throughput and drop signal from /realtime metrics</p>
          </div>
          <span className="observability-panel-code">CHART-01</span>
        </div>
        <div className="traffic-chart">
          <svg viewBox="0 0 720 270" role="img" aria-label="Traffic pressure chart">
            <path
              d={`${sparkPath(trafficValues, 680, 190)} L 680 220 L 0 220 Z`}
              transform="translate(20 22)"
              fill="rgba(6, 182, 212, 0.13)"
            />
            <path
              d={sparkPath(trafficValues, 680, 190)}
              transform="translate(20 22)"
              fill="none"
              stroke="#06b6d4"
              strokeWidth="3"
              strokeLinecap="round"
            />
            <path
              d={sparkPath(dropValues, 680, 150)}
              transform="translate(20 64)"
              fill="none"
              stroke="#f43f5e"
              strokeWidth="2"
              strokeLinecap="round"
              strokeDasharray="7 8"
            />
          </svg>
          <div className="chart-legend">
            <span><i className="legend-cyan" />Throughput</span>
            <span><i className="legend-red" />Drops</span>
          </div>
        </div>
      </article>

      <article className="chart-panel panel-inset">
        <div className="observability-panel-head">
          <div>
            <h2>Decision mix</h2>
            <p>Verdict split from firewall events</p>
          </div>
          <span className="observability-panel-code">CHART-02</span>
        </div>
        <div className="decision-mix">
          <div
            className="decision-donut"
            style={{
              background: `conic-gradient(#10b981 0 ${decisionMix.allow}%, #f59e0b ${decisionMix.allow}% ${decisionMix.allow + decisionMix.alert}%, #f43f5e ${decisionMix.allow + decisionMix.alert}% 100%)`,
            }}
          >
            <span>{eventsCount}</span>
            <small>events</small>
          </div>
          <div className="decision-list">
            <span><i className="legend-green" />Observe/decrypt {decisionMix.allow}%</span>
            <span><i className="legend-amber" />Alert/bypass {decisionMix.alert}%</span>
            <span><i className="legend-red" />Block/error {decisionMix.block}%</span>
          </div>
        </div>
      </article>
    </div>
  );
}
