import { useEffect, useState } from "react";
import { io } from "socket.io-client";
import type { FirewallEvent } from "../types/firewall/FirewallEvent";

const MAX_EVENTS = 100;

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

export function useFirewallEvents() {
  const [events, setEvents] = useState<FirewallEvent[]>([]);
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
    });

    return () => {
      socket.disconnect();
    };
  }, []);

  return { events, isConnected };
}
