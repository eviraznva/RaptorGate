import { useEffect, useState } from "react";
import type { Zone } from "../../types/zones/Zone";
import type { ZoneInterface } from "../../types/zones/ZoneInterface";
import type { EditZoneInterfaceBody } from "../../services/zoneInterfaces";

type ZoneInterfaceFormProps = {
  zoneInterface: ZoneInterface | null;
  isOpen: boolean;
  zones: Zone[];
  onClose: () => void;
  onSuccess: (id: string, body: EditZoneInterfaceBody) => void;
};

interface FormState {
  zoneId: string;
  vlanId: string;
  isActive: boolean;
  ipv4Address: string;
  ipv4Mask: string;
  ipv6Address: string;
  ipv6Mask: string;
}

interface FormErrors {
  zoneId?: string;
  ipv4Address?: string;
  ipv4Mask?: string;
  ipv6Mask?: string;
}

const EMPTY: FormState = {
  zoneId: "",
  vlanId: "",
  isActive: true,
  ipv4Address: "",
  ipv4Mask: "",
  ipv6Address: "",
  ipv6Mask: "",
};

function parseAddresses(addresses: string[]): {
  ipv4Address: string;
  ipv4Mask: string;
  ipv6Address: string;
  ipv6Mask: string;
} {
  let ipv4Address = "";
  let ipv4Mask = "";
  let ipv6Address = "";
  let ipv6Mask = "";

  for (const addr of addresses) {
    const [ip, mask] = addr.split("/");
    if (ip.includes(":")) {
      if (!ipv6Address) {
        ipv6Address = ip;
        ipv6Mask = mask ?? "";
      }
    } else {
      if (!ipv4Address) {
        ipv4Address = ip;
        ipv4Mask = mask ?? "";
      }
    }
  }

  return { ipv4Address, ipv4Mask, ipv6Address, ipv6Mask };
}

function fromZoneInterface(zi: ZoneInterface): FormState {
  const parsed = parseAddresses(zi.addresses);
  return {
    zoneId: zi.zoneId,
    vlanId: zi.vlanId !== null ? String(zi.vlanId) : "",
    isActive: zi.status === "active",
    ...parsed,
  };
}

function validate(f: FormState): FormErrors {
  const e: FormErrors = {};
  if (!f.zoneId) e.zoneId = "Required";
  if (f.ipv4Address && !f.ipv4Mask)
    e.ipv4Mask = "Mask required when address is set";
  if (f.ipv4Mask && !f.ipv4Address)
    e.ipv4Address = "Address required when mask is set";
  if (f.ipv6Address && !f.ipv6Mask)
    e.ipv6Mask = "Mask required when address is set";
  return e;
}

function toBody(f: FormState): EditZoneInterfaceBody {
  return {
    zoneId: f.zoneId,
    vlanId: f.vlanId !== "" ? Number(f.vlanId) : null,
    ipv4Address: f.ipv4Address || null,
    ipv4Mask: f.ipv4Mask !== "" ? Number(f.ipv4Mask) : null,
    ipv6Address: f.ipv6Address || null,
    ipv6Mask: f.ipv6Mask !== "" ? Number(f.ipv6Mask) : null,
    isActive: f.isActive,
  };
}

function previewAddress(f: FormState): string {
  if (f.ipv4Address && f.ipv4Mask) return `${f.ipv4Address}/${f.ipv4Mask}`;
  if (f.ipv6Address && f.ipv6Mask) return `${f.ipv6Address}/${f.ipv6Mask}`;
  return "no address";
}

export default function ZoneInterfaceForm({
  zoneInterface,
  isOpen,
  zones,
  onClose,
  onSuccess,
}: ZoneInterfaceFormProps) {
  const [form, setForm] = useState<FormState>(EMPTY);
  const [errors, setErrors] = useState<FormErrors>({});

  useEffect(() => {
    if (isOpen) {
      setForm(zoneInterface ? fromZoneInterface(zoneInterface) : EMPTY);
      setErrors({});
    }
  }, [isOpen, zoneInterface]);

  function setField<K extends keyof FormState>(key: K, value: FormState[K]) {
    setForm((prev) => ({ ...prev, [key]: value }));
    if (errors[key as keyof FormErrors]) {
      setErrors((prev) => ({ ...prev, [key]: undefined }));
    }
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const errs = validate(form);
    if (Object.keys(errs).length > 0) {
      setErrors(errs);
      return;
    }
    if (!zoneInterface) return;
    onSuccess(zoneInterface.id, toBody(form));
  }

  const selectedZone = zones.find((z) => z.id === form.zoneId);

  return (
    <>
      <div
        className="fixed inset-0 z-40 bg-black/70 transition-opacity duration-200"
        style={{ opacity: isOpen ? 1 : 0, pointerEvents: isOpen ? "auto" : "none" }}
        onClick={onClose}
        aria-hidden="true"
      />

      <div
        className="fixed inset-y-0 right-0 z-50 w-[480px] max-w-full bg-[#161616] border-l border-[#262626] flex flex-col transition-transform duration-200 ease-in-out"
        style={{ transform: isOpen ? "translateX(0)" : "translateX(100%)" }}
        role="dialog"
        aria-modal="true"
        aria-label="Edit zone interface"
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#262626] flex-shrink-0">
          <div>
            <div className="text-[9px] text-[#4a4a4a] tracking-[0.4em] uppercase mb-0.5">
              Editing
            </div>
            <div className="text-[13px] tracking-[0.3em] uppercase text-[#f5f5f5]">
              Edit Zone Interface
            </div>
            {zoneInterface && (
              <div className="text-[10px] text-[#06b6d4] font-mono mt-0.5 tracking-wider">
                {zoneInterface.interfaceName} ·{" "}
                {zoneInterface.id.slice(0, 8)}…
              </div>
            )}
          </div>
          <button
            type="button"
            onClick={onClose}
            className="text-[#4a4a4a] hover:text-[#f5f5f5] transition-colors text-lg leading-none p-1"
            aria-label="Close"
          >
            ✕
          </button>
        </div>

        {/* Body */}
        <form
          onSubmit={handleSubmit}
          className="flex-1 overflow-y-auto px-6 py-5 space-y-5"
        >
          {/* Zone select */}
          <div>
            <label className="block text-[10px] text-[#8a8a8a] uppercase tracking-[0.25em] mb-1.5">
              Assigned Zone <span className="text-[#f43f5e]">*</span>
            </label>
            <select
              className="input text-sm appearance-none cursor-pointer"
              value={form.zoneId}
              onChange={(e) => setField("zoneId", e.target.value)}
            >
              <option value="">— Select zone —</option>
              {zones.map((z) => (
                <option key={z.id} value={z.id}>
                  {z.name}
                  {!z.isActive ? " (inactive)" : ""}
                </option>
              ))}
            </select>
            {errors.zoneId && (
              <p className="text-[10px] text-[#f43f5e] mt-1 tracking-wider">
                {errors.zoneId}
              </p>
            )}
          </div>

          {/* VLAN + Active */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-[10px] text-[#8a8a8a] uppercase tracking-[0.25em] mb-1.5">
                VLAN
              </label>
              <input
                type="number"
                min={1}
                max={4094}
                placeholder="untagged"
                className="input text-sm w-full"
                value={form.vlanId}
                onChange={(e) => setField("vlanId", e.target.value)}
              />
            </div>

            <div>
              <label className="block text-[10px] text-[#8a8a8a] uppercase tracking-[0.25em] mb-1.5">
                Active
              </label>
              <div className="flex">
                <button
                  type="button"
                  onClick={() => setField("isActive", true)}
                  className={`flex-1 py-2.5 text-[10px] uppercase tracking-[0.2em] border transition-colors ${
                    form.isActive
                      ? "text-[#10b981] border-[#10b981]/40 bg-[#10b981]/10"
                      : "text-[#4a4a4a] border-[#262626] hover:text-[#8a8a8a]"
                  }`}
                >
                  Yes
                </button>
                <button
                  type="button"
                  onClick={() => setField("isActive", false)}
                  className={`flex-1 py-2.5 text-[10px] uppercase tracking-[0.2em] border-t border-b border-r transition-colors ${
                    !form.isActive
                      ? "text-[#f43f5e] border-[#f43f5e]/40 bg-[#f43f5e]/10"
                      : "text-[#4a4a4a] border-[#262626] hover:text-[#8a8a8a]"
                  }`}
                >
                  No
                </button>
              </div>
            </div>
          </div>

          {/* IPv4 */}
          <div>
            <label className="block text-[10px] text-[#8a8a8a] uppercase tracking-[0.25em] mb-1.5">
              IPv4
            </label>
            <div className="grid grid-cols-[1fr_80px] gap-2">
              <div>
                <input
                  type="text"
                  placeholder="10.20.0.1"
                  className="input text-sm w-full"
                  value={form.ipv4Address}
                  onChange={(e) => setField("ipv4Address", e.target.value)}
                />
                {errors.ipv4Address && (
                  <p className="text-[10px] text-[#f43f5e] mt-1 tracking-wider">
                    {errors.ipv4Address}
                  </p>
                )}
              </div>
              <div>
                <input
                  type="number"
                  min={0}
                  max={32}
                  placeholder="24"
                  className="input text-sm w-full"
                  value={form.ipv4Mask}
                  onChange={(e) => setField("ipv4Mask", e.target.value)}
                />
                {errors.ipv4Mask && (
                  <p className="text-[10px] text-[#f43f5e] mt-1 tracking-wider">
                    {errors.ipv4Mask}
                  </p>
                )}
              </div>
            </div>
          </div>

          {/* IPv6 */}
          <div>
            <label className="block text-[10px] text-[#8a8a8a] uppercase tracking-[0.25em] mb-1.5">
              IPv6
            </label>
            <div className="grid grid-cols-[1fr_80px] gap-2">
              <div>
                <input
                  type="text"
                  placeholder="fd00:20::1"
                  className="input text-sm w-full"
                  value={form.ipv6Address}
                  onChange={(e) => setField("ipv6Address", e.target.value)}
                />
              </div>
              <div>
                <input
                  type="number"
                  min={0}
                  max={128}
                  placeholder="64"
                  className="input text-sm w-full"
                  value={form.ipv6Mask}
                  onChange={(e) => setField("ipv6Mask", e.target.value)}
                />
                {errors.ipv6Mask && (
                  <p className="text-[10px] text-[#f43f5e] mt-1 tracking-wider">
                    {errors.ipv6Mask}
                  </p>
                )}
              </div>
            </div>
          </div>

          {/* Preview */}
          <div>
            <div className="text-[10px] text-[#8a8a8a] uppercase tracking-[0.25em] mb-1.5">
              Preview
            </div>
            <div className="border border-[#262626] bg-[#101010] p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[#f5f5f5] text-sm font-bold">
                  {zoneInterface?.interfaceName ?? "—"}
                </span>
                <span
                  className={`text-[10px] uppercase tracking-[0.15em] ${form.isActive ? "text-[#10b981]" : "text-[#f43f5e]"}`}
                >
                  {form.isActive ? "active" : "inactive"}
                </span>
              </div>
              <div className="flex items-center justify-between text-[11px]">
                <span className="text-[#4a4a4a]">zone</span>
                <span className="text-[#f5f5f5]">
                  {selectedZone?.name ?? "—"}
                </span>
              </div>
              <div className="flex items-center justify-between text-[11px]">
                <span className="text-[#4a4a4a]">network</span>
                <span className="text-[#06b6d4] font-mono text-[10px]">
                  {previewAddress(form)}
                </span>
              </div>
              {form.vlanId && (
                <div className="flex items-center justify-between text-[11px]">
                  <span className="text-[#4a4a4a]">vlan</span>
                  <span className="text-[#06b6d4]">VLAN {form.vlanId}</span>
                </div>
              )}
            </div>
          </div>
        </form>

        {/* Footer */}
        <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-[#262626] flex-shrink-0">
          <button
            type="button"
            onClick={onClose}
            className="px-5 py-2 text-[10px] uppercase tracking-[0.25em] text-[#8a8a8a] hover:text-[#f5f5f5] border border-[#262626] hover:border-[#4a4a4a] transition-colors"
          >
            Cancel
          </button>
          <button
            type="submit"
            onClick={handleSubmit}
            className="btn-primary px-5 py-2 text-[10px] uppercase tracking-[0.25em]"
          >
            Save Interface
          </button>
        </div>
      </div>
    </>
  );
}
