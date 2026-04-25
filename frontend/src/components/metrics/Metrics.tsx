import { useFirewallEvents } from "../../hooks/useFirewallEvents";
import type { FirewallEvent } from "../../types/firewall/FirewallEvent";

function formatTime(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(new Date(value));
}

function formatEndpoint(event: FirewallEvent, side: "src" | "dst"): string {
  const ip = side === "src" ? event.src_ip : event.dst_ip;
  const port = side === "src" ? event.src_port : event.dst_port;

  if (!ip) return "unknown";
  return port ? `${ip}:${port}` : ip;
}

function severityClass(event: FirewallEvent): string {
  if (event.decision === "block") return "border-[#f43f5e] text-[#f43f5e]";
  if (event.decision === "alert") return "border-[#f59e0b] text-[#f59e0b]";
  return "border-[#06b6d4] text-[#06b6d4]";
}

export function Metrics() {
  const { events, isConnected } = useFirewallEvents();

  return (
    <div className="min-h-screen bg-[#0c0c0c] flex flex-col text-[#f5f5f5]">
      <div className="flex-1 flex justify-center p-8">
        <div className="w-full max-w-6xl">
          <div className="flex items-center justify-center mb-10">
            <div className="flex-1 h-px bg-gradient-to-r from-transparent via-[#06b6d4] to-transparent" />
            <span className="px-4 text-[#06b6d4] text-xs">
              ◄──────────── FIREWALL EVENTS ────────────►
            </span>
            <div className="flex-1 h-px bg-gradient-to-r from-transparent via-[#06b6d4] to-transparent" />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-[1fr_360px] gap-6">
            <section className="bg-[#161616] border border-[#262626] p-5">
              <div className="flex items-center mb-4 text-sm">
                <span className="text-[#06b6d4] mr-2">◄</span>
                LIVE FIREWALL STREAM
                <span className="ml-auto text-xs text-[#8a8a8a]">
                  {isConnected ? "connected" : "disconnected"}
                </span>
              </div>

              <div className="space-y-2 max-h-[560px] overflow-auto pr-2">
                {events.length === 0 ? (
                  <div className="border border-dashed border-[#333] p-6 text-center text-sm text-[#8a8a8a]">
                    Waiting for firewall events
                  </div>
                ) : (
                  events.map((event) => (
                    <div
                      key={`${event.timestamp}:${event.signature_id ?? event.event_type}:${event.src_port ?? ""}`}
                      className={`border-l-2 bg-[#101010] px-4 py-3 ${severityClass(event)}`}
                    >
                      <div className="flex flex-wrap items-center gap-2 text-sm text-[#f5f5f5]">
                        <span className="text-[#8a8a8a] w-20">
                          {formatTime(event.timestamp)}
                        </span>
                        <span className="uppercase text-xs tracking-widest text-[#06b6d4]">
                          {event.source}
                        </span>
                        <span className="uppercase text-xs tracking-widest">
                          {event.decision}
                        </span>
                        <span className="ml-auto text-xs text-[#8a8a8a]">
                          {event.transport_protocol ?? ""}/{event.app_protocol ?? ""}
                        </span>
                      </div>

                      <div className="mt-2 text-sm">
                        <span>{formatEndpoint(event, "src")}</span>
                        <span className="mx-2 text-[#06b6d4]">-&gt;</span>
                        <span>{formatEndpoint(event, "dst")}</span>
                      </div>

                      <div className="mt-2 text-xs text-[#8a8a8a]">
                        {event.signature_name ?? event.event_type}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </section>

            <aside className="bg-[#161616] border border-[#262626] p-5">
              <div className="flex items-center mb-4 text-sm">
                IPS ALERTS
                <span className="ml-auto text-[#06b6d4]">────────►</span>
              </div>

              <div className="space-y-3">
                {events
                  .filter((event) => event.source === "IPS")
                  .slice(0, 8)
                  .map((event) => (
                    <div
                      key={`${event.timestamp}:${event.signature_id ?? event.signature_name}`}
                      className="border-l-2 border-[#f43f5e] pl-3"
                    >
                      <div className="text-sm text-[#f5f5f5]">
                        {event.severity ?? "unknown"} / {event.action ?? event.decision}
                      </div>
                      <div className="text-xs text-[#8a8a8a]">
                        {event.signature_name ?? "IPS signature matched"}
                      </div>
                      <div className="text-xs text-[#4a4a4a] mt-1">
                        {event.interface ?? "iface?"} / {event.payload_length ?? 0} bytes
                      </div>
                    </div>
                  ))}
              </div>
            </aside>
          </div>

          <div className="mt-10 text-center text-xs text-[#4a4a4a]">
            Dashboard module
            <span className="text-[#06b6d4] mx-3">|</span>
            Live firewall event monitoring
            <span className="text-[#06b6d4] mx-3">|</span>
            RaptorGate UI
          </div>
        </div>
      </div>
    </div>
  );
}
