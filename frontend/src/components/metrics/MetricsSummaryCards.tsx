import type { RealtimeMetric } from "./metricsTypes";
import {
  fallbackDrops,
  formatAge,
  formatMetric,
  latestMetric,
  metricSeries,
  sparkPath,
} from "./metricsUtils";

type MetricsSummaryCardsProps = {
  dropValues: number[];
  metrics: RealtimeMetric[];
  now: number;
  trafficValues: number[];
};

function Sparkline({ values, tone = "#06b6d4" }: { values: number[]; tone?: string }) {
  const path = sparkPath(values, 96, 30);

  return (
    <svg className="metric-sparkline" viewBox="0 0 96 30" aria-hidden="true">
      <path d={`${path} L 96 30 L 0 30 Z`} fill={tone} opacity="0.13" />
      <path d={path} fill="none" stroke={tone} strokeWidth="2" strokeLinecap="round" />
    </svg>
  );
}

export default function MetricsSummaryCards({
  dropValues,
  metrics,
  now,
  trafficValues,
}: MetricsSummaryCardsProps) {
  const throughputMetric = latestMetric(metrics, "throughput");
  const cpuMetric = latestMetric(metrics, "cpu");
  const memoryMetric = latestMetric(metrics, "memory");
  const dropsMetric = latestMetric(metrics, "drops");

  return (
    <div className="metrics-grid">
      <article className="metric-card">
        <span className="metric-label">Throughput</span>
        <strong>{formatMetric(throughputMetric, "-- Mbps")}</strong>
        <span className="metric-delta good">
          {throughputMetric ? formatAge(throughputMetric.timestamp, now) : "awaiting sample"}
        </span>
        <Sparkline values={trafficValues} />
      </article>
      <article className="metric-card">
        <span className="metric-label">CPU load</span>
        <strong>{formatMetric(cpuMetric, "-- %")}</strong>
        <span className="metric-delta">
          {cpuMetric ? formatAge(cpuMetric.timestamp, now) : "awaiting sample"}
        </span>
        <Sparkline
          values={metricSeries(metrics, "cpu", [31, 34, 38, 35, 42, 47, 44, 49, 46, 51])}
          tone="#10b981"
        />
      </article>
      <article className="metric-card">
        <span className="metric-label">Memory pressure</span>
        <strong>{formatMetric(memoryMetric, "-- %")}</strong>
        <span className="metric-delta warn">
          {memoryMetric ? formatAge(memoryMetric.timestamp, now) : "awaiting sample"}
        </span>
        <Sparkline
          values={metricSeries(metrics, "memory", [48, 51, 53, 52, 58, 61, 59, 64, 62, 66])}
          tone="#f59e0b"
        />
      </article>
      <article className="metric-card">
        <span className="metric-label">Drops</span>
        <strong>{formatMetric(dropsMetric, "-- pps")}</strong>
        <span className="metric-delta status-danger">
          {dropsMetric ? formatAge(dropsMetric.timestamp, now) : "awaiting sample"}
        </span>
        <Sparkline values={dropValues.length > 0 ? dropValues : fallbackDrops} tone="#f43f5e" />
      </article>
    </div>
  );
}
