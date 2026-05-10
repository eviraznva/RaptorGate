import { useMemo } from "react";
import {
  Area,
  AreaChart,
  ResponsiveContainer,
} from "recharts";
import type { RealtimeMetric } from "./metricsTypes";
import {
  formatAge,
  formatMetric,
  latestMetric,
  metricSeries,
} from "./metricsUtils";

type MetricsSummaryCardsProps = {
  dropValues: number[];
  metrics: RealtimeMetric[];
  now: number;
  trafficValues: number[];
};

type SparklinePoint = {
  sample: string;
  value: number;
};

const miniChartMargin = { bottom: 0, left: 0, right: 0, top: 2 };

function MiniMetricChart({ values, tone = "#06b6d4" }: { values: number[]; tone?: string }) {
  const data = useMemo<SparklinePoint[]>(
    () => values.map((value, index) => ({ sample: `${index + 1}`, value })),
    [values],
  );

  if (data.length === 0) {
    return <span className="metric-sparkline-empty">no live samples</span>;
  }

  return (
    <div className="metric-sparkline" aria-hidden="true">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={miniChartMargin}>
          <Area
            dataKey="value"
            dot={data.length === 1 ? { fill: tone, r: 2 } : false}
            fill={tone}
            fillOpacity={0.13}
            isAnimationActive={false}
            stroke={tone}
            strokeWidth={2}
            type="monotone"
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
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
  const cpuValues = useMemo(() => metricSeries(metrics, "cpu"), [metrics]);
  const memoryValues = useMemo(() => metricSeries(metrics, "memory"), [metrics]);

  return (
    <div className="metrics-grid">
      <article className="metric-card">
        <span className="metric-label">Throughput</span>
        <strong>{formatMetric(throughputMetric)}</strong>
        <span className="metric-delta good">
          {throughputMetric ? formatAge(throughputMetric.timestamp, now) : "awaiting live sample"}
        </span>
        <MiniMetricChart values={trafficValues} />
      </article>
      <article className="metric-card">
        <span className="metric-label">CPU load</span>
        <strong>{formatMetric(cpuMetric)}</strong>
        <span className="metric-delta">
          {cpuMetric ? formatAge(cpuMetric.timestamp, now) : "awaiting live sample"}
        </span>
        <MiniMetricChart values={cpuValues} tone="#10b981" />
      </article>
      <article className="metric-card">
        <span className="metric-label">Memory pressure</span>
        <strong>{formatMetric(memoryMetric)}</strong>
        <span className="metric-delta warn">
          {memoryMetric ? formatAge(memoryMetric.timestamp, now) : "awaiting live sample"}
        </span>
        <MiniMetricChart values={memoryValues} tone="#f59e0b" />
      </article>
      <article className="metric-card">
        <span className="metric-label">Drops</span>
        <strong>{formatMetric(dropsMetric)}</strong>
        <span className="metric-delta status-danger">
          {dropsMetric ? formatAge(dropsMetric.timestamp, now) : "awaiting live sample"}
        </span>
        <MiniMetricChart values={dropValues} tone="#f43f5e" />
      </article>
    </div>
  );
}
