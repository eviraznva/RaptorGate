import type { IpsGeneralConfig } from "../../../types/ipsConfig/IpsConfig";
import Toggle from "../common/Toggle";

type GeneralTabProps = {
  config: IpsGeneralConfig;
  onEnabledChange: (enabled: boolean) => void;
};

export default function GeneralTab({ config, onEnabledChange }: GeneralTabProps) {
  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <Toggle
        label="Enable IPS module"
        checked={config.enabled}
        onToggle={onEnabledChange}
      />
    </div>
  );
}

