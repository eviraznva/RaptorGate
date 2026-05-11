import { ipsTabs, type IpsTabKey } from "../../types/ipsConfig/IpsConfig";

type IpsTabsProps = {
  activeTab: IpsTabKey;
  onTabChange: (tab: IpsTabKey) => void;
};

export default function IpsTabs({ activeTab, onTabChange }: IpsTabsProps) {
  return (
    <div className="flex overflow-x-auto border-b border-[#262626]">
      {ipsTabs.map((tab) => (
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

