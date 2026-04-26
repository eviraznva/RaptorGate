import type { Zone } from "../../types/zones/Zone";
import type { ZoneInterface } from "../../types/zones/ZoneInterface";
import type { ZonePair } from "../../types/zones/ZonePair";
import type { ZonesTabKey } from "./ZonesTabs";

type ZonesStatusBarProps = {
  activeTab: ZonesTabKey;
  zones: Zone[];
  zonePairs: ZonePair[];
  zoneInterfaces: ZoneInterface[];
};

function ActiveDot() {
  return (
    <span className="relative flex items-center gap-1.5 text-[#10b981]">
      <span className="relative flex h-1.5 w-1.5">
        <span
          className="absolute inline-flex h-full w-full rounded-full bg-[#10b981]"
          style={{ animation: "pingSlow 2s ease-in-out infinite" }}
        />
        <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-[#10b981]" />
      </span>
      ACTIVE
    </span>
  );
}

export default function ZonesStatusBar({
  activeTab,
  zones,
  zonePairs,
  zoneInterfaces,
}: ZonesStatusBarProps) {
  const activeZones = zones.filter((z) => z.isActive).length;
  const allowPairs = zonePairs.filter((p) => p.defaultPolicy === "ALLOW").length;
  const dropPairs = zonePairs.filter((p) => p.defaultPolicy === "DROP").length;
  const activeInterfaces = zoneInterfaces.filter(
    (zoneInterface) => zoneInterface.status === "active",
  ).length;
  const missingInterfaces = zoneInterfaces.filter(
    (zoneInterface) => zoneInterface.status === "missing",
  ).length;

  return (
    <div className="bg-[#161616] border border-[#262626] px-5 py-3 mb-4 flex flex-wrap items-center gap-5 text-[11px]">
      <div className="flex items-center gap-2">
        <span className="text-[#8a8a8a] uppercase tracking-[0.2em]">Module</span>
        <ActiveDot />
      </div>
      <span className="text-[#262626]">│</span>

      {activeTab === "zones" ? (
        <>
          <div className="flex items-center gap-2">
            <span className="text-[#8a8a8a]">Total</span>
            <span className="text-[#f5f5f5] font-mono tabular-nums">
              {zones.length}
            </span>
          </div>
          <span className="text-[#262626]">│</span>
          <div className="flex items-center gap-2">
            <span className="text-[#8a8a8a]">Active</span>
            <span className="text-[#10b981] font-mono tabular-nums">
              {activeZones}
            </span>
          </div>
          <span className="text-[#262626]">│</span>
          <div className="flex items-center gap-2">
            <span className="text-[#8a8a8a]">Inactive</span>
            <span className="text-[#4a4a4a] font-mono tabular-nums">
              {zones.length - activeZones}
            </span>
          </div>
        </>
      ) : activeTab === "zone-pairs" ? (
        <>
          <div className="flex items-center gap-2">
            <span className="text-[#8a8a8a]">Total pairs</span>
            <span className="text-[#f5f5f5] font-mono tabular-nums">
              {zonePairs.length}
            </span>
          </div>
          <span className="text-[#262626]">│</span>
          <div className="flex items-center gap-2">
            <span className="text-[#8a8a8a]">Allow</span>
            <span className="text-[#10b981] font-mono tabular-nums">
              {allowPairs}
            </span>
          </div>
          <span className="text-[#262626]">│</span>
          <div className="flex items-center gap-2">
            <span className="text-[#8a8a8a]">Drop</span>
            <span className="text-[#f43f5e] font-mono tabular-nums">
              {dropPairs}
            </span>
          </div>
        </>
      ) : (
        <>
          <div className="flex items-center gap-2">
            <span className="text-[#8a8a8a]">Interfaces</span>
            <span className="text-[#f5f5f5] font-mono tabular-nums">
              {zoneInterfaces.length}
            </span>
          </div>
          <span className="text-[#262626]">│</span>
          <div className="flex items-center gap-2">
            <span className="text-[#8a8a8a]">Active</span>
            <span className="text-[#10b981] font-mono tabular-nums">
              {activeInterfaces}
            </span>
          </div>
          <span className="text-[#262626]">│</span>
          <div className="flex items-center gap-2">
            <span className="text-[#8a8a8a]">Missing</span>
            <span className="text-[#f43f5e] font-mono tabular-nums">
              {missingInterfaces}
            </span>
          </div>
        </>
      )}
    </div>
  );
}
