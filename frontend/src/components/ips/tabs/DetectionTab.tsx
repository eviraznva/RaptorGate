import type { IpsDetectionConfig } from "../../../types/ipsConfig/IpsConfig";
import Toggle from "../common/Toggle";

type DetectionTabProps = {
  config: IpsDetectionConfig;
  onConfigChange: (partial: Partial<IpsDetectionConfig>) => void;
};

function toInt(value: string): number {
  const parsed = Number.parseInt(value, 10);
  return Number.isNaN(parsed) ? 0 : parsed;
}

export default function DetectionTab({
  config,
  onConfigChange,
}: DetectionTabProps) {
  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <Toggle
        label="Enable packet inspection detection"
        checked={config.enabled}
        onToggle={(enabled) => onConfigChange({ enabled })}
      />

      <label className="text-sm">
        <div className="text-[#8a8a8a] mb-2">Max payload bytes</div>
        <input
          type="number"
          value={config.maxPayloadBytes}
          onChange={(event) =>
            onConfigChange({ maxPayloadBytes: toInt(event.target.value) })
          }
          className="w-full bg-[#0c0c0c] border border-[#262626] px-4 py-3 focus:outline-none focus:border-[#06b6d4]"
        />
      </label>

      <label className="text-sm">
        <div className="text-[#8a8a8a] mb-2">Max matches per packet</div>
        <input
          type="number"
          value={config.maxMatchesPerPacket}
          onChange={(event) =>
            onConfigChange({ maxMatchesPerPacket: toInt(event.target.value) })
          }
          className="w-full bg-[#0c0c0c] border border-[#262626] px-4 py-3 focus:outline-none focus:border-[#06b6d4]"
        />
      </label>
    </div>
  );
}

