import { Icon } from "@iconify/react";
import type { ZoneInterfaceStatus } from "../../types/zones/ZoneInterface";

export type ZoneInterfaceFilter = "all" | Extract<ZoneInterfaceStatus, "active" | "missing">;

const FILTERS: { key: ZoneInterfaceFilter; label: string }[] = [
  { key: "all", label: "All" },
  { key: "active", label: "Active" },
  { key: "missing", label: "Missing" },
];

type ZoneInterfacesToolbarProps = {
  visibleCount: number;
  search: string;
  filter: ZoneInterfaceFilter;
  isRefreshing: boolean;
  onSearchChange: (value: string) => void;
  onFilterChange: (filter: ZoneInterfaceFilter) => void;
  onRefresh: () => void;
};

export default function ZoneInterfacesToolbar({
  visibleCount,
  search,
  filter,
  isRefreshing,
  onSearchChange,
  onFilterChange,
  onRefresh,
}: ZoneInterfacesToolbarProps) {
  return (
    <div className="flex flex-col gap-4 mb-4 xl:flex-row xl:items-start xl:justify-between">
      <div>
        <div className="text-[11px] tracking-[0.25em] uppercase">
          Live Interface Matrix
        </div>
        <div className="text-[10px] text-[#4a4a4a] tracking-[0.12em] uppercase mt-1">
          {visibleCount} visible
          <span className="text-[#262626] mx-2">/</span>
          gRPC liveZoneInterfaces
        </div>
      </div>

      <div className="flex flex-col gap-2 sm:flex-row sm:items-center xl:justify-end">
        <label className="flex items-center gap-2 bg-[#101010] border border-[#262626] px-3 h-9 min-w-0 sm:w-[340px] focus-within:border-[#06b6d4] transition-colors">
          <Icon icon="lucide:search" width="15" height="15" className="text-[#4a4a4a] flex-shrink-0" />
          <input
            value={search}
            onChange={(event) => onSearchChange(event.target.value)}
            placeholder="Filter interface, zone, address"
            className="w-full min-w-0 bg-transparent outline-none text-[#f5f5f5] placeholder:text-[#4a4a4a] text-xs"
          />
        </label>

        <div className="flex h-9 bg-[#101010] border border-[#262626]">
          {FILTERS.map((item) => (
            <button
              key={item.key}
              type="button"
              onClick={() => onFilterChange(item.key)}
              className={`px-3 min-w-20 text-[10px] uppercase tracking-[0.16em] border-r border-[#262626] last:border-r-0 transition-colors ${
                filter === item.key
                  ? "text-black bg-[#06b6d4]"
                  : "text-[#8a8a8a] hover:text-[#f5f5f5]"
              }`}
            >
              {item.label}
            </button>
          ))}
        </div>

        <button
          type="button"
          onClick={onRefresh}
          className="grid place-items-center h-9 w-9 border border-[#06b6d4] text-[#06b6d4] hover:text-black hover:bg-[#06b6d4] transition-colors"
          title="Refresh live interfaces"
        >
          <Icon
            icon="lucide:refresh-cw"
            width="16"
            height="16"
            className={isRefreshing ? "animate-spin" : ""}
          />
        </button>
      </div>
    </div>
  );
}
