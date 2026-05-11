import { useEffect, useState } from "react";
import type { Zone } from "../../types/zones/Zone";

type ZoneFormProps = {
  zone: Zone | null;
  isOpen: boolean;
  onClose: () => void;
  onSuccess: (zone: Zone, mode: "create" | "edit") => void;
};

interface FormState {
  name: string;
  description: string;
  isActive: boolean;
}

interface FormErrors {
  name?: string;
  description?: string;
}

const EMPTY: FormState = { name: "", description: "", isActive: true };

function fromZone(z: Zone): FormState {
  return { name: z.name, description: z.description, isActive: z.isActive };
}

function validate(f: FormState): FormErrors {
  const e: FormErrors = {};

  if (!f.name.trim()) e.name = "Required";
  else if (f.name.length > 128) e.name = "Max 128 chars";

  if (!f.description.trim()) e.description = "Required";

  return e;
}

export default function ZoneForm({
  zone,
  isOpen,
  onClose,
  onSuccess,
}: ZoneFormProps) {
  const isEditMode = zone !== null;
  const [form, setForm] = useState<FormState>(EMPTY);
  const [errors, setErrors] = useState<FormErrors>({});

  useEffect(() => {
    if (isOpen) {
      setForm(zone ? fromZone(zone) : EMPTY);
      setErrors({});
    }
  }, [isOpen, zone]);

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

    const result: Zone = {
      id: zone?.id ?? crypto.randomUUID(),
      name: form.name.trim(),
      description: form.description.trim(),
      isActive: form.isActive,
      createdAt: zone?.createdAt ?? new Date().toISOString(),
      createdBy: zone?.createdBy ?? "current-user",
    };

    onSuccess(result, isEditMode ? "edit" : "create");
  }

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 z-40 bg-black/70 transition-opacity duration-200"
        style={{
          opacity: isOpen ? 1 : 0,
          pointerEvents: isOpen ? "auto" : "none",
        }}
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Drawer */}
      <div
        className="fixed inset-y-0 right-0 z-50 w-[480px] max-w-full bg-[#161616] border-l border-[#262626] flex flex-col transition-transform duration-200 ease-in-out"
        style={{ transform: isOpen ? "translateX(0)" : "translateX(100%)" }}
        role="dialog"
        aria-modal="true"
        aria-label={isEditMode ? "Edit zone" : "New zone"}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#262626] flex-shrink-0">
          <div>
            <div className="text-[9px] text-[#4a4a4a] tracking-[0.4em] uppercase mb-0.5">
              {isEditMode ? "Editing" : "Creating"}
            </div>
            <div className="text-[13px] tracking-[0.3em] uppercase text-[#f5f5f5]">
              {isEditMode ? "Edit Zone" : "New Zone"}
            </div>
            {isEditMode && (
              <div className="text-[10px] text-[#06b6d4] font-mono mt-0.5 tracking-wider">
                {zone.name}
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
          {/* Name */}
          <div>
            <label className="block text-[10px] text-[#8a8a8a] uppercase tracking-[0.25em] mb-1.5">
              Name <span className="text-[#f43f5e]">*</span>
            </label>
            <input
              className="input text-sm"
              type="text"
              value={form.name}
              onChange={(e) => setField("name", e.target.value)}
              placeholder="e.g. DMZ, LAN, WAN"
              maxLength={128}
              autoComplete="off"
            />
            {errors.name && (
              <p className="text-[10px] text-[#f43f5e] mt-1 tracking-wider">
                {errors.name}
              </p>
            )}
          </div>

          {/* Description */}
          <div>
            <label className="block text-[10px] text-[#8a8a8a] uppercase tracking-[0.25em] mb-1.5">
              Description <span className="text-[#f43f5e]">*</span>
            </label>
            <textarea
              className="input text-sm resize-none"
              rows={3}
              value={form.description}
              onChange={(e) => setField("description", e.target.value)}
              placeholder="Describe the purpose of this network zone…"
            />
            {errors.description && (
              <p className="text-[10px] text-[#f43f5e] mt-1 tracking-wider">
                {errors.description}
              </p>
            )}
          </div>

          {/* Is Active toggle */}
          <div className="flex items-center justify-between py-3 border-t border-[#262626]">
            <div>
              <div className="text-[10px] text-[#8a8a8a] uppercase tracking-[0.25em]">
                Active
              </div>
              <div className="text-[10px] text-[#4a4a4a] mt-0.5">
                Zone will be available for zone pair assignment
              </div>
            </div>
            <button
              type="button"
              role="switch"
              aria-checked={form.isActive}
              onClick={() => setField("isActive", !form.isActive)}
              className="relative inline-flex h-5 w-9 flex-shrink-0 items-center rounded-full transition-colors duration-150 focus:outline-none"
              style={{ backgroundColor: form.isActive ? "#06b6d4" : "#2a2a2a" }}
            >
              <span
                className="inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow transition-transform duration-150"
                style={{
                  transform: form.isActive
                    ? "translateX(18px)"
                    : "translateX(2px)",
                }}
              />
            </button>
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
            {isEditMode ? "Save Changes" : "Create Zone"}
          </button>
        </div>
      </div>
    </>
  );
}
