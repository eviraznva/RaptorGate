import type { ZoneInterface } from "../../types/zones/ZoneInterface";

type ZoneInterfacesOverviewProps = {
  zoneInterfaces: ZoneInterface[];
};

function uniqueVlans(zoneInterfaces: ZoneInterface[]) {
  return Array.from(
    new Set(
      zoneInterfaces
        .map((zoneInterface) => zoneInterface.vlanId)
        .filter((vlanId): vlanId is number => vlanId !== null),
    ),
  );
}

function ratio(part: number, total: number) {
  if (total === 0) return 0;

  return Math.round((part / total) * 100);
}

export default function ZoneInterfacesOverview({
  zoneInterfaces,
}: ZoneInterfacesOverviewProps) {
  const total = zoneInterfaces.length;
  const active = zoneInterfaces.filter(
    (zoneInterface) => zoneInterface.status === "active",
  ).length;
  const addressed = zoneInterfaces.filter(
    (zoneInterface) => zoneInterface.addresses.length > 0,
  ).length;
  const vlans = uniqueVlans(zoneInterfaces);
  const linkRatio = ratio(active, total);
  const addressedRatio = ratio(addressed, total);

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-4">
      <div className="bg-[#101010] border border-[#262626] p-4">
        <div className="text-[10px] text-[#4a4a4a] tracking-[0.2em] uppercase">
          Link State
        </div>
        <div className="flex items-end gap-2 mt-3">
          <span className="text-3xl tabular-nums">{linkRatio}</span>
          <span className="text-[10px] text-[#4a4a4a] uppercase tracking-[0.15em] mb-1">
            %
          </span>
        </div>
        <div className="h-1 bg-[#242424] mt-4 overflow-hidden">
          <div
            className="h-full bg-[#10b981] transition-[width]"
            style={{ width: `${linkRatio}%` }}
          />
        </div>
      </div>

      <div className="bg-[#101010] border border-[#262626] p-4">
        <div className="text-[10px] text-[#4a4a4a] tracking-[0.2em] uppercase">
          Addressed
        </div>
        <div className="flex items-end gap-2 mt-3">
          <span className="text-3xl tabular-nums">{addressed}</span>
          <span className="text-[10px] text-[#4a4a4a] uppercase tracking-[0.15em] mb-1">
            ports
          </span>
        </div>
        <div className="h-1 bg-[#242424] mt-4 overflow-hidden">
          <div
            className="h-full bg-[#06b6d4] transition-[width]"
            style={{ width: `${addressedRatio}%` }}
          />
        </div>
      </div>

      <div className="bg-[#101010] border border-[#262626] p-4">
        <div className="text-[10px] text-[#4a4a4a] tracking-[0.2em] uppercase">
          VLANs
        </div>
        <div className="flex items-end gap-2 mt-3">
          <span className="text-3xl tabular-nums">{vlans.length}</span>
          <span className="text-[10px] text-[#4a4a4a] uppercase tracking-[0.15em] mb-1">
            tagged
          </span>
        </div>
        <div className="flex flex-wrap gap-1 mt-4">
          {vlans.length === 0 ? (
            <span className="text-[10px] text-[#4a4a4a]">untagged only</span>
          ) : (
            vlans.map((vlanId) => (
              <span
                key={vlanId}
                className="border border-[#06b6d4]/40 bg-[#06b6d4]/10 text-[#06b6d4] text-[9px] px-1.5 py-1 leading-none"
              >
                {vlanId}
              </span>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
