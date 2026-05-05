import { useMemo, useState } from "react";
import type { Zone } from "../../types/zones/Zone";
import type { ZoneInterface } from "../../types/zones/ZoneInterface";
import ZoneInterfacesOverview from "./ZoneInterfacesOverview";
import ZoneInterfacesSignalRail from "./ZoneInterfacesSignalRail";
import ZoneInterfacesTable from "./ZoneInterfacesTable";
import ZoneInterfacesToolbar, {
  type ZoneInterfaceFilter,
} from "./ZoneInterfacesToolbar";

type ZoneInterfacesViewProps = {
  zoneInterfaces: ZoneInterface[];
  zones: Zone[];
  isRefreshing: boolean;
  onRefresh: () => void;
  onEdit: (zoneInterface: ZoneInterface) => void;
};

function matchesSearch(zoneInterface: ZoneInterface, search: string) {
  const term = search.trim().toLowerCase();
  if (!term) return true;

  return [
    zoneInterface.interfaceName,
    zoneInterface.zoneId,
    zoneInterface.status,
    String(zoneInterface.vlanId ?? "untagged"),
    ...zoneInterface.addresses,
  ].some((value) => value.toLowerCase().includes(term));
}

export default function ZoneInterfacesView({
  zoneInterfaces,
  isRefreshing,
  onRefresh,
  onEdit,
}: ZoneInterfacesViewProps) {
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<ZoneInterfaceFilter>("all");

  const filteredZoneInterfaces = useMemo(
    () =>
      zoneInterfaces.filter((zoneInterface) => {
        if (filter !== "all" && zoneInterface.status !== filter) return false;

        return matchesSearch(zoneInterface, search);
      }),
    [filter, search, zoneInterfaces],
  );

  const visibleIds = useMemo(
    () =>
      new Set(
        filteredZoneInterfaces.map((zoneInterface) => zoneInterface.id),
      ),
    [filteredZoneInterfaces],
  );

  return (
    <>
      <ZoneInterfacesToolbar
        visibleCount={filteredZoneInterfaces.length}
        search={search}
        filter={filter}
        isRefreshing={isRefreshing}
        onSearchChange={setSearch}
        onFilterChange={setFilter}
        onRefresh={onRefresh}
      />
      <ZoneInterfacesOverview zoneInterfaces={zoneInterfaces} />
      <div className="grid grid-cols-1 lg:grid-cols-[210px_minmax(0,1fr)] gap-3">
        <ZoneInterfacesSignalRail
          zoneInterfaces={zoneInterfaces}
          visibleIds={visibleIds}
        />
        <ZoneInterfacesTable
          zoneInterfaces={filteredZoneInterfaces}
          onEdit={onEdit}
        />
      </div>
    </>
  );
}
