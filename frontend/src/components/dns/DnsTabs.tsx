import { dnsTabs, type DnsTabKey } from "../../types/dnsInspection/DnsInspectionConfig";

type DnsTabsProps = {
  activeTab: DnsTabKey;
  onTabChange: (tab: DnsTabKey) => void;
};

export default function DnsTabs({ activeTab, onTabChange }: DnsTabsProps) {
  return (
    <div className="flex overflow-x-auto border-b border-[#262626]">
      {dnsTabs.map((tab) => (
        <button
          key={tab.key}
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
