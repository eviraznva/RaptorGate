import { useEffect, useState } from "react";
import { io } from "socket.io-client";
import type { FirewallEvent } from "../types/firewall/FirewallEvent";

const MAX_EVENTS = 100;

function resolveAlertsUrl(): { url: string; path: string } {
  const envUrl = import.meta.env.RAPTOR_GATE_ALERTS_WS_URL;
  if (envUrl) {
    const u = new URL(envUrl);
    return { url: `${u.origin}/alerts`, path: `${u.pathname}/socket.io`.replace(/\/+/g, "/") };
  }
  return { url: `${window.location.origin}/alerts`, path: "/alerts/socket.io" };
}

export function useFirewallEvents() {
  const [events, setEvents] = useState<FirewallEvent[]>([]);
  const [isConnected, setIsConnected] = useState(false);

  useEffect(() => {
    const { url, path } = resolveAlertsUrl();
    const socket = io(url, {
      path,
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
    });

    return () => {
      socket.disconnect();
    };
  }, []);

  return { events, isConnected };
}
