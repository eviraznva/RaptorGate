import type {
  DnsInspectionDnssecCacheConfig,
  DnsInspectionDnssecCacheTtlConfig,
  DnsInspectionDnssecConfig,
  DnsInspectionDnssecResolverConfig,
  DnsInspectionDnssecResolverEndpoint,
  DnssecFailureAction,
  DnssecTransport,
} from "../../../types/dnsInspection/DnsInspectionConfig";
import Toggle from "../common/Toggle";

type DnssecTabProps = {
  config: DnsInspectionDnssecConfig;
  onConfigChange: (partial: Partial<DnsInspectionDnssecConfig>) => void;
  onResolverChange: (partial: Partial<DnsInspectionDnssecResolverConfig>) => void;
  onPrimaryResolverChange: (partial: Partial<DnsInspectionDnssecResolverEndpoint>) => void;
  onSecondaryResolverChange: (partial: Partial<DnsInspectionDnssecResolverEndpoint>) => void;
  onCacheChange: (partial: Partial<DnsInspectionDnssecCacheConfig>) => void;
  onCacheTtlChange: (partial: Partial<DnsInspectionDnssecCacheTtlConfig>) => void;
};

function toInt(value: string): number {
  const parsed = Number.parseInt(value, 10);
  return Number.isNaN(parsed) ? 0 : parsed;
}

export default function DnssecTab({
  config,
  onConfigChange,
  onResolverChange,
  onPrimaryResolverChange,
  onSecondaryResolverChange,
  onCacheChange,
  onCacheTtlChange,
}: DnssecTabProps) {
  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <Toggle
        label="Enable DNSSEC verification"
        checked={config.enabled}
        onToggle={(enabled) => onConfigChange({ enabled })}
      />

      <label className="text-sm">
        <div className="text-[#8a8a8a] mb-2">Max lookups per packet</div>
        <input
          type="number"
          value={config.maxLookupsPerPacket}
          onChange={(event) => onConfigChange({ maxLookupsPerPacket: toInt(event.target.value) })}
          className="w-full bg-[#0c0c0c] border border-[#262626] px-4 py-3 focus:outline-none focus:border-[#06b6d4]"
        />
      </label>

      <label className="text-sm">
        <div className="text-[#8a8a8a] mb-2">Failure action</div>
        <select
          value={config.defaultOnResolverFailure}
          onChange={(event) =>
            onConfigChange({
              defaultOnResolverFailure: event.target.value as DnssecFailureAction,
            })
          }
          className="w-full bg-[#0c0c0c] border border-[#262626] px-4 py-3 focus:outline-none focus:border-[#06b6d4]"
        >
          <option value="allow">ALLOW</option>
          <option value="alert">ALERT</option>
          <option value="block">BLOCK</option>
        </select>
      </label>

      <label className="text-sm">
        <div className="text-[#8a8a8a] mb-2">Primary resolver address</div>
        <input
          type="text"
          value={config.resolver.primary.address}
          onChange={(event) => onPrimaryResolverChange({ address: event.target.value })}
          className="w-full bg-[#0c0c0c] border border-[#262626] px-4 py-3 focus:outline-none focus:border-[#06b6d4]"
        />
      </label>

      <label className="text-sm">
        <div className="text-[#8a8a8a] mb-2">Primary resolver port</div>
        <input
          type="number"
          value={config.resolver.primary.port}
          onChange={(event) => onPrimaryResolverChange({ port: toInt(event.target.value) })}
          className="w-full bg-[#0c0c0c] border border-[#262626] px-4 py-3 focus:outline-none focus:border-[#06b6d4]"
        />
      </label>

      <label className="text-sm">
        <div className="text-[#8a8a8a] mb-2">Secondary resolver address (optional)</div>
        <input
          type="text"
          value={config.resolver.secondary.address}
          onChange={(event) => onSecondaryResolverChange({ address: event.target.value })}
          className="w-full bg-[#0c0c0c] border border-[#262626] px-4 py-3 focus:outline-none focus:border-[#06b6d4]"
        />
      </label>

      <label className="text-sm">
        <div className="text-[#8a8a8a] mb-2">Secondary resolver port</div>
        <input
          type="number"
          value={config.resolver.secondary.port}
          onChange={(event) => onSecondaryResolverChange({ port: toInt(event.target.value) })}
          className="w-full bg-[#0c0c0c] border border-[#262626] px-4 py-3 focus:outline-none focus:border-[#06b6d4]"
        />
      </label>

      <label className="text-sm">
        <div className="text-[#8a8a8a] mb-2">Transport</div>
        <select
          value={config.resolver.transport}
          onChange={(event) =>
            onResolverChange({ transport: event.target.value as DnssecTransport })
          }
          className="w-full bg-[#0c0c0c] border border-[#262626] px-4 py-3 focus:outline-none focus:border-[#06b6d4]"
        >
          <option value="udp">UDP</option>
          <option value="tcp">TCP</option>
          <option value="udpWithTcpFallback">UDP with TCP fallback</option>
        </select>
      </label>

      <label className="text-sm">
        <div className="text-[#8a8a8a] mb-2">Timeout (ms)</div>
        <input
          type="number"
          value={config.resolver.timeoutMs}
          onChange={(event) => onResolverChange({ timeoutMs: toInt(event.target.value) })}
          className="w-full bg-[#0c0c0c] border border-[#262626] px-4 py-3 focus:outline-none focus:border-[#06b6d4]"
        />
      </label>

      <label className="text-sm">
        <div className="text-[#8a8a8a] mb-2">Retries</div>
        <input
          type="number"
          value={config.resolver.retries}
          onChange={(event) => onResolverChange({ retries: toInt(event.target.value) })}
          className="w-full bg-[#0c0c0c] border border-[#262626] px-4 py-3 focus:outline-none focus:border-[#06b6d4]"
        />
      </label>

      <Toggle
        label="Enable DNSSEC cache"
        checked={config.cache.enabled}
        onToggle={(enabled) => onCacheChange({ enabled })}
      />

      <label className="text-sm">
        <div className="text-[#8a8a8a] mb-2">Cache max entries</div>
        <input
          type="number"
          value={config.cache.maxEntries}
          onChange={(event) => onCacheChange({ maxEntries: toInt(event.target.value) })}
          className="w-full bg-[#0c0c0c] border border-[#262626] px-4 py-3 focus:outline-none focus:border-[#06b6d4]"
        />
      </label>

      <label className="text-sm">
        <div className="text-[#8a8a8a] mb-2">TTL secure (s)</div>
        <input
          type="number"
          value={config.cache.ttlSeconds.secure}
          onChange={(event) => onCacheTtlChange({ secure: toInt(event.target.value) })}
          className="w-full bg-[#0c0c0c] border border-[#262626] px-4 py-3 focus:outline-none focus:border-[#06b6d4]"
        />
      </label>

      <label className="text-sm">
        <div className="text-[#8a8a8a] mb-2">TTL insecure (s)</div>
        <input
          type="number"
          value={config.cache.ttlSeconds.insecure}
          onChange={(event) => onCacheTtlChange({ insecure: toInt(event.target.value) })}
          className="w-full bg-[#0c0c0c] border border-[#262626] px-4 py-3 focus:outline-none focus:border-[#06b6d4]"
        />
      </label>

      <label className="text-sm">
        <div className="text-[#8a8a8a] mb-2">TTL bogus (s)</div>
        <input
          type="number"
          value={config.cache.ttlSeconds.bogus}
          onChange={(event) => onCacheTtlChange({ bogus: toInt(event.target.value) })}
          className="w-full bg-[#0c0c0c] border border-[#262626] px-4 py-3 focus:outline-none focus:border-[#06b6d4]"
        />
      </label>

      <label className="text-sm">
        <div className="text-[#8a8a8a] mb-2">TTL failure (s)</div>
        <input
          type="number"
          value={config.cache.ttlSeconds.failure}
          onChange={(event) => onCacheTtlChange({ failure: toInt(event.target.value) })}
          className="w-full bg-[#0c0c0c] border border-[#262626] px-4 py-3 focus:outline-none focus:border-[#06b6d4]"
        />
      </label>
    </div>
  );
}
