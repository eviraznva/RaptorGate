import type { DnsInspectionBlocklistConfig } from "../../../types/dnsInspection/DnsInspectionConfig";
import Toggle from "../common/Toggle";

type BlocklistTabProps = {
  config: DnsInspectionBlocklistConfig;
  onEnabledChange: (enabled: boolean) => void;
  onDomainsChange: (domains: string[]) => void;
};

export default function BlocklistTab({
  config,
  onEnabledChange,
  onDomainsChange,
}: BlocklistTabProps) {
  const domainsText = config.domains.join("\n");

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <Toggle
        label="Enable blocklist checks"
        checked={config.enabled}
        onToggle={onEnabledChange}
      />

      <div className="lg:col-span-2">
        <div className="text-xs text-[#8a8a8a] mb-2">Blocked domains (one per line)</div>
        <textarea
          value={domainsText}
          onChange={(event) =>
            onDomainsChange(
              event.target.value
                .split("\n")
                .map((value) => value.trim())
                .filter(Boolean),
            )
          }
          rows={8}
          className="w-full bg-[#0c0c0c] border border-[#262626] px-4 py-3 text-white focus:outline-none focus:border-[#06b6d4]"
          placeholder={"example.com\n*.tracking.local"}
        />
      </div>
    </div>
  );
}
