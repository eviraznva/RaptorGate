export type MetricsTabKey = "metrics" | "alerts" | "logs";

export type RealtimeMetric = {
  name: string;
  value: number;
  unit: string;
  timestamp: string;
};

export type AlertTone = {
  color: string;
  soft: string;
  className: string;
  label: string;
};

export type MetricsStats = {
  alerting: number;
  blocked: number;
  eventsPerMinute: number;
};

export type DecisionMix = {
  alert: number;
  allow: number;
  block: number;
};

export type AlertDetailRow = {
  label: string;
  value: string;
  tone?: string;
};
