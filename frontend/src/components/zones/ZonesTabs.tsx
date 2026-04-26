export type ZonesTabKey = "zones" | "zone-pairs" | "zone-interfaces";

const tabs: { key: ZonesTabKey; label: string }[] = [
  { key: "zones", label: "Zones" },
  { key: "zone-pairs", label: "Zone Pairs" },
  { key: "zone-interfaces", label: "Zone Interfaces" },
];

type ZonesTabsProps = {
  activeTab: ZonesTabKey;
  onTabChange: (tab: ZonesTabKey) => void;
};

export default function ZonesTabs({ activeTab, onTabChange }: ZonesTabsProps) {
  return (
    <div className="flex overflow-x-auto border-b border-[#262626]">
      {tabs.map((tab) => (
        <button
          key={tab.key}
          type="button"
          onClick={() => onTabChange(tab.key)}
          className={`px-4 py-3 text-sm whitespace-nowrap transition ${
            activeTab === tab.key
              ? "text-[#06b6d4] border-b-2 border-[#06b6d4]"
              : "text-[#8a8a8a] hover:text-white"
          }`}
        >
          {tab.label}
        </button>
      ))}
    </div>
  );
}
