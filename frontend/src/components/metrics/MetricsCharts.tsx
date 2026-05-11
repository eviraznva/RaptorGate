import { useMemo } from "react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  Cell,
  Line,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { DecisionMix } from "./metricsTypes";

type MetricsChartsProps = {
  decisionMix: DecisionMix;
  eventsCount: number;
  dropValues: number[];
  trafficValues: number[];
};

type TrafficChartPoint = {
  drops?: number;
  sample: string;
  throughput?: number;
};

const decisionColors = {
  alert: "#f59e0b",
  allow: "#10b981",
  block: "#f43f5e",
};

const tooltipContentStyle = {
  background: "#101010",
  border: "1px solid #262626",
  color: "#f5f5f5",
};

const trafficChartMargin = { bottom: 8, left: 0, right: 12, top: 18 };

function buildTrafficData(trafficValues: number[], dropValues: number[]): TrafficChartPoint[] {
  const samples = Math.max(trafficValues.length, dropValues.length);

  return Array.from({ length: samples }, (_, index) => ({
    drops: dropValues[index],
    sample: `${index + 1}`,
    throughput: trafficValues[index],
  }));
}

export default function MetricsCharts({
  decisionMix,
  eventsCount,
  dropValues,
  trafficValues,
}: MetricsChartsProps) {
  const trafficData = useMemo(
    () => buildTrafficData(trafficValues, dropValues),
    [dropValues, trafficValues],
  );
  const hasTrafficData = trafficData.length > 0;
  const decisionData = useMemo(
    () =>
      [
        { color: decisionColors.allow, name: "Observe/decrypt", value: decisionMix.allow },
        { color: decisionColors.alert, name: "Alert/bypass", value: decisionMix.alert },
        { color: decisionColors.block, name: "Block/error", value: decisionMix.block },
      ].filter((item) => item.value > 0),
    [decisionMix.alert, decisionMix.allow, decisionMix.block],
  );
  const hasDecisionData = eventsCount > 0 && decisionData.length > 0;

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
          {hasTrafficData ? (
            <div className="chart-frame">
              <ResponsiveContainer width="100%" height={310}>
                <AreaChart data={trafficData} margin={trafficChartMargin}>
                  <CartesianGrid stroke="rgba(255,255,255,0.07)" vertical={false} />
                  <XAxis dataKey="sample" hide />
                  <YAxis hide domain={["auto", "auto"]} />
                  <Tooltip
                    contentStyle={tooltipContentStyle}
                    cursor={{ stroke: "rgba(6, 182, 212, 0.35)" }}
                    labelFormatter={(label) => `Sample ${label}`}
                  />
                  <Area
                    dataKey="throughput"
                    dot={trafficValues.length === 1 ? { fill: "#06b6d4", r: 3 } : false}
                    fill="rgba(6, 182, 212, 0.13)"
                    name="Throughput"
                    stroke="#06b6d4"
                    strokeWidth={3}
                    type="monotone"
                  />
                  <Line
                    dataKey="drops"
                    dot={dropValues.length === 1 ? { fill: "#f43f5e", r: 3 } : false}
                    name="Drops"
                    stroke="#f43f5e"
                    strokeDasharray="7 8"
                    strokeWidth={2}
                    type="monotone"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="metrics-empty-state">No live metric samples</div>
          )}
          <div className="chart-legend">
            <span>
              <i className="legend-cyan" />
              Throughput
            </span>
            <span>
              <i className="legend-red" />
              Drops
            </span>
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
          {hasDecisionData ? (
            <div className="decision-chart-wrap">
              <ResponsiveContainer width="100%" height={250}>
                <PieChart>
                  <Pie
                    data={decisionData}
                    dataKey="value"
                    innerRadius="68%"
                    nameKey="name"
                    outerRadius="94%"
                    stroke="none"
                  >
                    {decisionData.map((entry) => (
                      <Cell fill={entry.color} key={entry.name} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={tooltipContentStyle}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div className="decision-chart-center">
                <span>{eventsCount}</span>
                <small>events</small>
              </div>
            </div>
          ) : (
            <div className="metrics-empty-state">No firewall events</div>
          )}
          <div className="decision-list">
            <span>
              <i className="legend-green" />
              Observe/decrypt {decisionMix.allow}%
            </span>
            <span>
              <i className="legend-amber" />
              Alert/bypass {decisionMix.alert}%
            </span>
            <span>
              <i className="legend-red" />
              Block/error {decisionMix.block}%
            </span>
          </div>
        </div>
      </article>
    </div>
  );
}
