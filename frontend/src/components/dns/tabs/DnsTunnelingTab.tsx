import type { DnsInspectionDnsTunnelingConfig } from "../../../types/dnsInspection/DnsInspectionConfig";
import Toggle from "../common/Toggle";

type DnsTunnelingTabProps = {
  config: DnsInspectionDnsTunnelingConfig;
  onConfigChange: (partial: Partial<DnsInspectionDnsTunnelingConfig>) => void;
  onIgnoreDomainsChange: (domains: string[]) => void;
};

function toInt(value: string): number {
  const parsed = Number.parseInt(value, 10);
  return Number.isNaN(parsed) ? 0 : parsed;
}

function toFloat(value: string): number {
  const parsed = Number.parseFloat(value);
  return Number.isNaN(parsed) ? 0 : parsed;
}

export default function DnsTunnelingTab({
  config,
  onConfigChange,
  onIgnoreDomainsChange,
}: DnsTunnelingTabProps) {
  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <Toggle
        label="Enable DNS tunneling detector"
        checked={config.enabled}
        onToggle={(enabled) => onConfigChange({ enabled })}
      />

      <label className="text-sm">
        <div className="text-[#8a8a8a] mb-2">Max label length</div>
        <input
          type="number"
          value={config.maxLabelLength}
          onChange={(event) => onConfigChange({ maxLabelLength: toInt(event.target.value) })}
          className="w-full bg-[#0c0c0c] border border-[#262626] px-4 py-3 focus:outline-none focus:border-[#06b6d4]"
        />
      </label>

      <label className="text-sm">
        <div className="text-[#8a8a8a] mb-2">Entropy threshold</div>
        <input
          type="number"
          step="0.01"
          value={config.entropyThreshold}
          onChange={(event) => onConfigChange({ entropyThreshold: toFloat(event.target.value) })}
          className="w-full bg-[#0c0c0c] border border-[#262626] px-4 py-3 focus:outline-none focus:border-[#06b6d4]"
        />
      </label>

      <label className="text-sm">
        <div className="text-[#8a8a8a] mb-2">Window seconds</div>
        <input
          type="number"
          value={config.windowSeconds}
          onChange={(event) => onConfigChange({ windowSeconds: toInt(event.target.value) })}
          className="w-full bg-[#0c0c0c] border border-[#262626] px-4 py-3 focus:outline-none focus:border-[#06b6d4]"
        />
      </label>

      <label className="text-sm">
        <div className="text-[#8a8a8a] mb-2">Max queries per domain</div>
        <input
          type="number"
          value={config.maxQueriesPerDomain}
          onChange={(event) => onConfigChange({ maxQueriesPerDomain: toInt(event.target.value) })}
          className="w-full bg-[#0c0c0c] border border-[#262626] px-4 py-3 focus:outline-none focus:border-[#06b6d4]"
        />
      </label>

      <label className="text-sm">
        <div className="text-[#8a8a8a] mb-2">Max unique subdomains</div>
        <input
          type="number"
          value={config.maxUniqueSubdomains}
          onChange={(event) => onConfigChange({ maxUniqueSubdomains: toInt(event.target.value) })}
          className="w-full bg-[#0c0c0c] border border-[#262626] px-4 py-3 focus:outline-none focus:border-[#06b6d4]"
        />
      </label>

      <label className="text-sm">
        <div className="text-[#8a8a8a] mb-2">Alert threshold (0..1)</div>
        <input
          type="number"
          step="0.01"
          min={0}
          max={1}
          value={config.alertThreshold}
          onChange={(event) => onConfigChange({ alertThreshold: toFloat(event.target.value) })}
          className="w-full bg-[#0c0c0c] border border-[#262626] px-4 py-3 focus:outline-none focus:border-[#06b6d4]"
        />
      </label>

      <label className="text-sm">
        <div className="text-[#8a8a8a] mb-2">Block threshold (0..1)</div>
        <input
          type="number"
          step="0.01"
          min={0}
          max={1}
          value={config.blockThreshold}
          onChange={(event) => onConfigChange({ blockThreshold: toFloat(event.target.value) })}
          className="w-full bg-[#0c0c0c] border border-[#262626] px-4 py-3 focus:outline-none focus:border-[#06b6d4]"
        />
      </label>

      <div className="lg:col-span-2">
        <div className="text-xs text-[#8a8a8a] mb-2">Ignore domains (one per line)</div>
        <textarea
          value={config.ignoreDomains.join("\n")}
          onChange={(event) =>
            onIgnoreDomainsChange(
              event.target.value
                .split("\n")
                .map((value) => value.trim())
                .filter(Boolean),
            )
          }
          rows={6}
          className="w-full bg-[#0c0c0c] border border-[#262626] px-4 py-3 text-white focus:outline-none focus:border-[#06b6d4]"
          placeholder="*.example.com"
        />
      </div>
    </div>
  );
}
