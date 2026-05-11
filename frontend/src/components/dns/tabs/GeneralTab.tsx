import type { DnsInspectionGeneralConfig } from "../../../types/dnsInspection/DnsInspectionConfig";
import Toggle from "../common/Toggle";

type GeneralTabProps = {
  config: DnsInspectionGeneralConfig;
  onEnabledChange: (enabled: boolean) => void;
};

export default function GeneralTab({ config, onEnabledChange }: GeneralTabProps) {
  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <Toggle
        label="Enable DNS Inspection module"
        checked={config.enabled}
        onToggle={onEnabledChange}
      />
    </div>
  );
}
