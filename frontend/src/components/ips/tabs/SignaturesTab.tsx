import { useState } from "react";
import type {
  IpsAppProtocol,
  IpsConfig,
  IpsSignatureConfig,
} from "../../../types/ipsConfig/IpsConfig";
import {
  ipsActionOptions,
  ipsAppProtocolOptions,
  ipsSeverityOptions,
} from "../../../types/ipsConfig/IpsConfig";
import Toggle from "../common/Toggle";

type PortsInputProps = {
  ports: number[];
  onChange: (ports: number[]) => void;
  placeholder?: string;
  className?: string;
};

function PortsInput({ ports, onChange, placeholder, className }: PortsInputProps) {
  const [raw, setRaw] = useState(() => ports.join(", "));
  const [prevPorts, setPrevPorts] = useState(ports);

  if (JSON.stringify(ports) !== JSON.stringify(prevPorts)) {
    setPrevPorts(ports);
    
    const parsedRaw = parsePortList(raw);
    if (JSON.stringify(parsedRaw) !== JSON.stringify(ports)) {
      setRaw(ports.length > 0 ? ports.join(", ") : "");
    }
  }

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    setRaw(value);
    
    const parsed = parsePortList(value);
    if (JSON.stringify(parsed) !== JSON.stringify(ports)) {
      onChange(parsed);
    }
  };

  const handleBlur = () => {
    const parsed = parsePortList(raw);
    if (JSON.stringify(parsed) !== JSON.stringify(ports)) {
      onChange(parsed);
    }
    setRaw(parsed.length > 0 ? parsed.join(", ") : "");
  };

  return (
    <input
      type="text"
      value={raw}
      onChange={handleChange}
      onBlur={handleBlur}
      placeholder={placeholder}
      className={className}
    />
  );
}

type SignaturesTabProps = {
  config: IpsConfig;
  selectedSignatureId: string | null;
  selectedSignature: IpsSignatureConfig | null;
  onSelectSignature: (id: string | null) => void;
  onAddSignature: () => void;
  onRemoveSignature: (id: string) => void;
  onUpdateSelectedSignature: (partial: Partial<IpsSignatureConfig>) => void;
  onUpdateProtocols: (protocols: IpsAppProtocol[]) => void;
  onUpdateSrcPorts: (ports: number[]) => void;
  onUpdateDstPorts: (ports: number[]) => void;
};

function parsePortList(raw: string): number[] {
  return raw
    .split(/[\s,]+/g)
    .map((token) => token.trim())
    .filter(Boolean)
    .map((token) => Number.parseInt(token, 10))
    .filter((value) => !Number.isNaN(value));
}

export default function SignaturesTab({
  config,
  selectedSignatureId,
  selectedSignature,
  onSelectSignature,
  onAddSignature,
  onRemoveSignature,
  onUpdateSelectedSignature,
  onUpdateProtocols,
  onUpdateSrcPorts,
  onUpdateDstPorts,
}: SignaturesTabProps) {
  return (
    <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
      <div className="border border-[#262626] bg-[#101010]">
        <div className="px-4 py-3 border-b border-[#262626] flex items-center gap-2">
          <span className="text-xs text-[#8a8a8a] uppercase tracking-widest">
            Signature table
          </span>
          <span className="ml-auto text-xs text-[#8a8a8a]">
            {config.signatures.length} total
          </span>
        </div>

        <div className="p-3 flex gap-2 border-b border-[#262626]">
          <button
            onClick={onAddSignature}
            className="px-3 py-2 bg-[#06b6d4] text-black text-xs font-medium hover:bg-[#0891b2]"
          >
            + ADD SIGNATURE
          </button>
          <button
            onClick={() =>
              selectedSignatureId && onRemoveSignature(selectedSignatureId)
            }
            disabled={!selectedSignatureId}
            className={`px-3 py-2 text-xs border ${
              selectedSignatureId
                ? "border-[#f43f5e] text-[#fca5a5] hover:bg-[#f43f5e]/10"
                : "border-[#262626] text-[#4a4a4a] cursor-not-allowed"
            }`}
          >
            REMOVE SELECTED
          </button>
        </div>

        <div className="max-h-[32rem] overflow-auto">
          <table className="w-full text-xs">
            <thead className="text-[#8a8a8a] border-b border-[#262626]">
              <tr>
                <th className="text-left p-3">EN</th>
                <th className="text-left p-3">ID</th>
                <th className="text-left p-3">NAME</th>
                <th className="text-left p-3">SEVERITY</th>
                <th className="text-left p-3">ACTION</th>
              </tr>
            </thead>
            <tbody>
              {config.signatures.map((signature) => (
                <tr
                  key={signature.id}
                  onClick={() => onSelectSignature(signature.id)}
                  className={`border-b border-[#262626] cursor-pointer ${
                    selectedSignatureId === signature.id
                      ? "bg-[#06b6d4]/10"
                      : "hover:bg-[#202020]"
                  }`}
                >
                  <td className="p-3">{signature.enabled ? "ON" : "OFF"}</td>
                  <td className="p-3 text-[#06b6d4]">{signature.id}</td>
                  <td className="p-3">{signature.name}</td>
                  <td className="p-3 uppercase">{signature.severity}</td>
                  <td className="p-3 uppercase">{signature.action}</td>
                </tr>
              ))}
            </tbody>
          </table>

          {config.signatures.length === 0 && (
            <div className="p-6 text-sm text-[#8a8a8a]">
              No signatures configured yet.
            </div>
          )}
        </div>
      </div>

      <div className="border border-[#262626] bg-[#101010] p-4">
        <div className="text-xs text-[#8a8a8a] uppercase tracking-widest mb-4">
          Signature editor
        </div>

        {!selectedSignature && (
          <div className="text-sm text-[#8a8a8a]">
            Select a signature from the table to edit fields.
          </div>
        )}

        {selectedSignature && (
          <div className="grid grid-cols-1 gap-4">
            <Toggle
              label="Signature enabled"
              checked={selectedSignature.enabled}
              onToggle={(enabled) => onUpdateSelectedSignature({ enabled })}
            />

            <label className="text-sm">
              <div className="text-[#8a8a8a] mb-2">Signature ID</div>
              <input
                type="text"
                value={selectedSignature.id}
                onChange={(event) =>
                  onUpdateSelectedSignature({ id: event.target.value })
                }
                className="w-full bg-[#0c0c0c] border border-[#262626] px-4 py-3 focus:outline-none focus:border-[#06b6d4]"
              />
            </label>

            <label className="text-sm">
              <div className="text-[#8a8a8a] mb-2">Name</div>
              <input
                type="text"
                value={selectedSignature.name}
                onChange={(event) =>
                  onUpdateSelectedSignature({ name: event.target.value })
                }
                className="w-full bg-[#0c0c0c] border border-[#262626] px-4 py-3 focus:outline-none focus:border-[#06b6d4]"
              />
            </label>

            <label className="text-sm">
              <div className="text-[#8a8a8a] mb-2">Category</div>
              <input
                type="text"
                value={selectedSignature.category}
                onChange={(event) =>
                  onUpdateSelectedSignature({ category: event.target.value })
                }
                className="w-full bg-[#0c0c0c] border border-[#262626] px-4 py-3 focus:outline-none focus:border-[#06b6d4]"
              />
            </label>

            <label className="text-sm">
              <div className="text-[#8a8a8a] mb-2">Pattern (regex)</div>
              <textarea
                value={selectedSignature.pattern}
                onChange={(event) =>
                  onUpdateSelectedSignature({ pattern: event.target.value })
                }
                rows={3}
                className="w-full bg-[#0c0c0c] border border-[#262626] px-4 py-3 text-white focus:outline-none focus:border-[#06b6d4]"
              />
            </label>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <label className="text-sm">
                <div className="text-[#8a8a8a] mb-2">Severity</div>
                <select
                  value={selectedSignature.severity}
                  onChange={(event) =>
                    onUpdateSelectedSignature({
                      severity: event.target.value as IpsSignatureConfig["severity"],
                    })
                  }
                  className="w-full bg-[#0c0c0c] border border-[#262626] px-4 py-3 focus:outline-none focus:border-[#06b6d4]"
                >
                  {ipsSeverityOptions.map((severity) => (
                    <option key={severity} value={severity}>
                      {severity.toUpperCase()}
                    </option>
                  ))}
                </select>
              </label>

              <label className="text-sm">
                <div className="text-[#8a8a8a] mb-2">Action</div>
                <select
                  value={selectedSignature.action}
                  onChange={(event) =>
                    onUpdateSelectedSignature({
                      action: event.target.value as IpsSignatureConfig["action"],
                    })
                  }
                  className="w-full bg-[#0c0c0c] border border-[#262626] px-4 py-3 focus:outline-none focus:border-[#06b6d4]"
                >
                  {ipsActionOptions.map((action) => (
                    <option key={action} value={action}>
                      {action.toUpperCase()}
                    </option>
                  ))}
                </select>
              </label>
            </div>

            <div>
              <div className="text-sm text-[#8a8a8a] mb-2">App protocols</div>
              <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                {ipsAppProtocolOptions.map((protocol) => {
                  const active = selectedSignature.appProtocols.includes(protocol);
                  return (
                    <button
                      key={protocol}
                      type="button"
                      onClick={() => {
                        const next = active
                          ? selectedSignature.appProtocols.filter(
                              (value) => value !== protocol,
                            )
                          : [...selectedSignature.appProtocols, protocol];
                        onUpdateProtocols(next);
                      }}
                      className={`px-3 py-2 text-xs border transition ${
                        active
                          ? "border-[#06b6d4] text-[#06b6d4] bg-[#06b6d4]/10"
                          : "border-[#262626] text-[#8a8a8a] hover:text-white"
                      }`}
                    >
                      {protocol.toUpperCase()}
                    </button>
                  );
                })}
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <label className="text-sm">
                <div className="text-[#8a8a8a] mb-2">Source ports</div>
                <PortsInput
                  ports={selectedSignature.srcPorts}
                  onChange={onUpdateSrcPorts}
                  placeholder="80, 443"
                  className="w-full bg-[#0c0c0c] border border-[#262626] px-4 py-3 focus:outline-none focus:border-[#06b6d4]"
                />
              </label>

              <label className="text-sm">
                <div className="text-[#8a8a8a] mb-2">Destination ports</div>
                <PortsInput
                  ports={selectedSignature.dstPorts}
                  onChange={onUpdateDstPorts}
                  placeholder="53, 8080"
                  className="w-full bg-[#0c0c0c] border border-[#262626] px-4 py-3 focus:outline-none focus:border-[#06b6d4]"
                />
              </label>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

