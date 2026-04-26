import type { ZoneInterface } from "../../types/zones/ZoneInterface";

type ZoneInterfacesSignalRailProps = {
  zoneInterfaces: ZoneInterface[];
  visibleIds: Set<string>;
};

function statusClass(status: ZoneInterface["status"]) {
  if (status === "active") return "bg-[#10b981] shadow-[0_0_8px_rgba(16,185,129,0.9)]";
  if (status === "missing") return "bg-[#f43f5e] shadow-[0_0_8px_rgba(244,63,94,0.75)]";
  if (status === "unknown") return "bg-[#f59e0b]";

  return "bg-[#4a4a4a]";
}

export default function ZoneInterfacesSignalRail({
  zoneInterfaces,
  visibleIds,
}: ZoneInterfacesSignalRailProps) {
  return (
    <aside className="bg-[#101010] border border-[#262626] p-4 min-h-[420px] lg:min-h-0">
      <div className="text-[10px] text-[#4a4a4a] tracking-[0.2em] uppercase mb-4">
        Signal Map
      </div>
      <div className="grid gap-2">
        {zoneInterfaces.map((zoneInterface) => (
          <div
            key={zoneInterface.id}
            className={`grid grid-cols-[10px_1fr_auto] items-center gap-2 min-h-7 text-[10px] text-[#8a8a8a] transition-opacity ${
              visibleIds.has(zoneInterface.id) ? "opacity-100" : "opacity-30"
            }`}
          >
            <span
              className={`w-2 h-2 rounded-full ${statusClass(zoneInterface.status)}`}
            />
            <span className="truncate">{zoneInterface.interfaceName}</span>
            <span className="text-[#4a4a4a] truncate max-w-16">
              {zoneInterface.zoneId}
            </span>
          </div>
        ))}
      </div>
    </aside>
  );
}
