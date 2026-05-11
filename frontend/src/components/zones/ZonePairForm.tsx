import { useEffect, useState } from "react";
import type { Zone } from "../../types/zones/Zone";
import type { DefaultPolicy, ZonePair } from "../../types/zones/ZonePair";

type ZonePairFormProps = {
  zonePair: ZonePair | null;
  isOpen: boolean;
  zones: Zone[];
  onClose: () => void;
  onSuccess: (pair: ZonePair, mode: "create" | "edit") => void;
};

interface FormState {
  srcZoneId: string;
  dstZoneId: string;
  defaultPolicy: DefaultPolicy;
}

interface FormErrors {
  srcZoneId?: string;
  dstZoneId?: string;
}

const EMPTY: FormState = { srcZoneId: "", dstZoneId: "", defaultPolicy: "ALLOW" };

function fromPair(p: ZonePair): FormState {
  return {
    srcZoneId: p.srcZoneId,
    dstZoneId: p.dstZoneId,
    defaultPolicy: p.defaultPolicy,
  };
}

function validate(f: FormState): FormErrors {
  const e: FormErrors = {};
  if (!f.srcZoneId) e.srcZoneId = "Required";
  if (!f.dstZoneId) e.dstZoneId = "Required";
  else if (f.srcZoneId && f.srcZoneId === f.dstZoneId)
    e.dstZoneId = "Must differ from source zone";
  return e;
}

function PolicyToggle({
  value,
  onChange,
}: {
  value: DefaultPolicy;
  onChange: (p: DefaultPolicy) => void;
}) {
  return (
    <div className="flex">
      <button
        type="button"
        onClick={() => onChange("ALLOW")}
        className={`flex-1 py-2.5 text-[10px] uppercase tracking-[0.2em] border transition-colors ${
          value === "ALLOW"
            ? "text-[#10b981] border-[#10b981]/40 bg-[#10b981]/10"
            : "text-[#4a4a4a] border-[#262626] hover:text-[#8a8a8a]"
        }`}
      >
        Allow
      </button>
      <button
        type="button"
        onClick={() => onChange("DROP")}
        className={`flex-1 py-2.5 text-[10px] uppercase tracking-[0.2em] border-t border-b border-r transition-colors ${
          value === "DROP"
            ? "text-[#f43f5e] border-[#f43f5e]/40 bg-[#f43f5e]/10"
            : "text-[#4a4a4a] border-[#262626] hover:text-[#8a8a8a]"
        }`}
      >
        Drop
      </button>
    </div>
  );
}

export default function ZonePairForm({
  zonePair,
  isOpen,
  zones,
  onClose,
  onSuccess,
}: ZonePairFormProps) {
  const isEditMode = zonePair !== null;
  const [form, setForm] = useState<FormState>(EMPTY);
  const [errors, setErrors] = useState<FormErrors>({});

  useEffect(() => {
    if (isOpen) {
      setForm(zonePair ? fromPair(zonePair) : EMPTY);
      setErrors({});
    }
  }, [isOpen, zonePair]);

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

    const result: ZonePair = {
      id: zonePair?.id ?? crypto.randomUUID(),
      srcZoneId: form.srcZoneId,
      dstZoneId: form.dstZoneId,
      defaultPolicy: form.defaultPolicy,
      createdAt: zonePair?.createdAt ?? new Date().toISOString(),
      createdBy: zonePair?.createdBy ?? "current-user",
    };

    onSuccess(result, isEditMode ? "edit" : "create");
  }

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 z-40 bg-black/70 transition-opacity duration-200"
        style={{ opacity: isOpen ? 1 : 0, pointerEvents: isOpen ? "auto" : "none" }}
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Drawer */}
      <div
        className="fixed inset-y-0 right-0 z-50 w-[480px] max-w-full bg-[#161616] border-l border-[#262626] flex flex-col transition-transform duration-200 ease-in-out"
        style={{ transform: isOpen ? "translateX(0)" : "translateX(100%)" }}
        role="dialog"
        aria-modal="true"
        aria-label={isEditMode ? "Edit zone pair" : "New zone pair"}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#262626] flex-shrink-0">
          <div>
            <div className="text-[9px] text-[#4a4a4a] tracking-[0.4em] uppercase mb-0.5">
              {isEditMode ? "Editing" : "Creating"}
            </div>
            <div className="text-[13px] tracking-[0.3em] uppercase text-[#f5f5f5]">
              {isEditMode ? "Edit Zone Pair" : "New Zone Pair"}
            </div>
            {isEditMode && (
              <div className="text-[10px] text-[#06b6d4] font-mono mt-0.5 tracking-wider">
                {zonePair.id.slice(0, 8)}…
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
          {/* Source Zone */}
          <div>
            <label className="block text-[10px] text-[#8a8a8a] uppercase tracking-[0.25em] mb-1.5">
              Source Zone <span className="text-[#f43f5e]">*</span>
            </label>
            <select
              className="input text-sm appearance-none cursor-pointer"
              value={form.srcZoneId}
              onChange={(e) => setField("srcZoneId", e.target.value)}
            >
              <option value="">— Select source zone —</option>
              {zones.map((z) => (
                <option key={z.id} value={z.id}>
                  {z.name}
                  {!z.isActive ? " (inactive)" : ""}
                </option>
              ))}
            </select>
            {errors.srcZoneId && (
              <p className="text-[10px] text-[#f43f5e] mt-1 tracking-wider">
                {errors.srcZoneId}
              </p>
            )}
          </div>

          {/* Destination Zone */}
          <div>
            <label className="block text-[10px] text-[#8a8a8a] uppercase tracking-[0.25em] mb-1.5">
              Destination Zone <span className="text-[#f43f5e]">*</span>
            </label>
            <select
              className="input text-sm appearance-none cursor-pointer"
              value={form.dstZoneId}
              onChange={(e) => setField("dstZoneId", e.target.value)}
            >
              <option value="">— Select destination zone —</option>
              {zones.map((z) => (
                <option key={z.id} value={z.id}>
                  {z.name}
                  {!z.isActive ? " (inactive)" : ""}
                </option>
              ))}
            </select>
            {errors.dstZoneId && (
              <p className="text-[10px] text-[#f43f5e] mt-1 tracking-wider">
                {errors.dstZoneId}
              </p>
            )}
          </div>

          {/* Default Policy */}
          <div>
            <label className="block text-[10px] text-[#8a8a8a] uppercase tracking-[0.25em] mb-1.5">
              Default Policy <span className="text-[#f43f5e]">*</span>
              <span className="text-[#4a4a4a] ml-2 normal-case tracking-normal">
                applied when no rule matches
              </span>
            </label>
            <PolicyToggle
              value={form.defaultPolicy}
              onChange={(p) => setField("defaultPolicy", p)}
            />
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
            {isEditMode ? "Save Changes" : "Create Pair"}
          </button>
        </div>
      </div>
    </>
  );
}
