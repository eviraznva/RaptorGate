import { useEffect, useState } from "react";
import { io } from "socket.io-client";
import type { FirewallEvent } from "../../types/firewall/FirewallEvent";
import type { RealtimeMetric } from "./metricsTypes";
import { firewallAlertId, isFirewallAlert } from "./metricsUtils";

const MAX_EVENTS = 160;
const MAX_ALERTS = 80;
const MAX_METRICS = 120;

function getRealtimeUrl(): string {
  const apiUrl = import.meta.env.RAPTOR_GATE_API_URL ?? window.location.origin;
  const normalizedApiUrl = apiUrl.replace(/\/$/, "");

  if (normalizedApiUrl === "/api") {
    return `${window.location.origin}/realtime`;
  }

  if (normalizedApiUrl.endsWith("/api")) {
    return `${normalizedApiUrl.slice(0, -4)}/realtime`;
  }

  return `${normalizedApiUrl}/realtime`;
}

export function useRealtimeObservability() {
  const [events, setEvents] = useState<FirewallEvent[]>([]);
  const [alerts, setAlerts] = useState<FirewallEvent[]>([]);
  const [metrics, setMetrics] = useState<RealtimeMetric[]>([]);
  const [isConnected, setIsConnected] = useState(false);

  useEffect(() => {
    const socket = io(getRealtimeUrl(), {
      withCredentials: true,
      transports: ["websocket"],
    });

    socket.on("connect", () => {
      setIsConnected(true);
    });

    socket.on("disconnect", () => {
      setIsConnected(false);
    });

    socket.on("firewall-events", (event: FirewallEvent) => {
      setEvents((current) => [event, ...current].slice(0, MAX_EVENTS));
      if (isFirewallAlert(event)) {
        setAlerts((current) =>
          [
            event,
            ...current.filter((item) => firewallAlertId(item) !== firewallAlertId(event)),
          ].slice(0, MAX_ALERTS),
        );
      }
    });

    socket.on("metrics", (metric: RealtimeMetric) => {
      setMetrics((current) => [metric, ...current].slice(0, MAX_METRICS));
    });

    return () => {
      socket.disconnect();
    };
  }, []);

  return { alerts, events, isConnected, metrics };
}
