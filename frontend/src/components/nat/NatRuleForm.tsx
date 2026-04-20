import { useEffect, useState } from "react";
import type { NatRule, NatType } from "../../types/nat/NatRule";

type NatRuleFormProps = {
  rule: NatRule | null;
  isOpen: boolean;
  onClose: () => void;
  onSuccess: (rule: NatRule, mode: "create" | "edit") => void;
};

interface FormState {
  type: NatType;
  isActive: boolean;
  priority: string;
  sourceIp: string;
  sourcePort: string;
  destinationIp: string;
  destinationPort: string;
  translatedIp: string;
  translatedPort: string;
}

interface FormErrors {
  priority?: string;
  sourcePort?: string;
  destinationPort?: string;
  translatedPort?: string;
}

const EMPTY: FormState = {
  type: "SNAT",
  isActive: true,
  priority: "10",
  sourceIp: "",
  sourcePort: "",
  destinationIp: "",
  destinationPort: "",
  translatedIp: "",
  translatedPort: "",
};

const TYPE_HINTS: Record<NatType, string> = {
  SNAT: "Source NAT — rewrites the source IP/port of outgoing packets.",
  DNAT: "Destination NAT — rewrites the destination IP/port of incoming packets.",
  PAT:  "Port Address Translation — maps many private IPs to a single public IP using ports.",
};

function fromRule(r: NatRule): FormState {
  return {
    type:            r.type,
    isActive:        r.isActive,
    priority:        String(r.priority),
    sourceIp:        r.sourceIp        ?? "",
    sourcePort:      r.sourcePort      !== null ? String(r.sourcePort)      : "",
    destinationIp:   r.destinationIp   ?? "",
    destinationPort: r.destinationPort !== null ? String(r.destinationPort) : "",
    translatedIp:    r.translatedIp    ?? "",
    translatedPort:  r.translatedPort  !== null ? String(r.translatedPort)  : "",
  };
}

function validatePort(val: string): string | undefined {
  if (val === "") return undefined;
  const n = Number(val);
  if (!Number.isInteger(n) || n < 1 || n > 65535) return "Must be 1–65535";
  return undefined;
}

function toNullableInt(val: string): number | null {
  if (val === "") return null;
  const n = Number(val);
  return Number.isInteger(n) && n > 0 ? n : null;
}

function priorityColor(p: number) {
  return p <= 3 ? "#f43f5e" : p <= 7 ? "#f59e0b" : "#06b6d4";
}

// ── Type toggle button ── (module-level, rerender-no-inline-components)
const TYPE_ACTIVE_STYLES: Record<NatType, string> = {
  SNAT: "text-[#06b6d4] border-[#06b6d4]/40 bg-[#06b6d4]/12",
  DNAT: "text-[#f59e0b] border-[#f59e0b]/40 bg-[#f59e0b]/12",
  PAT:  "text-[#10b981] border-[#10b981]/40 bg-[#10b981]/12",
};

function TypeToggle({
  value,
  onChange,
}: {
  value: NatType;
  onChange: (t: NatType) => void;
}) {
  return (
    <div className="flex">
      {(["SNAT", "DNAT", "PAT"] as NatType[]).map((t, i) => (
        <button
          key={t}
          type="button"
          onClick={() => onChange(t)}
          className={`flex-1 py-2.5 text-[10px] uppercase tracking-[0.15em] border transition-colors
            ${i > 0 ? "border-l-0" : ""}
            ${value === t
              ? TYPE_ACTIVE_STYLES[t]
              : "text-[#4a4a4a] border-[#262626] hover:text-[#f5f5f5] hover:border-[#4a4a4a]"
            }`}
        >
          {t}
        </button>
      ))}
    </div>
  );
}

// ── Section label ──
function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div className="text-[9px] letter-spacing-[0.25em] uppercase text-[#4a4a4a] border-b border-[#262626] pb-1.5 mb-3 tracking-[0.25em]">
      {children}
    </div>
  );
}

// ── Field group ──
function FieldGroup({
  label,
  optional,
  error,
  children,
}: {
  label: string;
  optional?: boolean;
  error?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex flex-col gap-1.5">
      <label className="text-[9px] uppercase tracking-[0.2em] text-[#8a8a8a]">
        {label}
        {optional ? (
          <span className="text-[#4a4a4a] ml-1.5 text-[8px] normal-case tracking-normal">
            optional
          </span>
        ) : (
          <span className="text-[#f43f5e] ml-0.5">*</span>
        )}
      </label>
      {children}
      {error !== undefined ? (
        <p className="text-[10px] text-[#f43f5e] tracking-wider">{error}</p>
      ) : null}
    </div>
  );
}

export default function NatRuleForm({ rule, isOpen, onClose, onSuccess }: NatRuleFormProps) {
  const isEditMode = rule !== null;
  const [form, setForm] = useState<FormState>(EMPTY);
  const [errors, setErrors] = useState<FormErrors>({});

  useEffect(() => {
    if (isOpen) {
      setForm(rule ? fromRule(rule) : EMPTY);
      setErrors({});
    }
  }, [isOpen, rule]);

  function setField<K extends keyof FormState>(key: K, value: FormState[K]) {
    setForm((prev) => ({ ...prev, [key]: value }));
    if (key in errors) {
      setErrors((prev) => ({ ...prev, [key]: undefined }));
    }
  }

  function handleTypeChange(t: NatType) {
    setForm((prev) => ({
      ...prev,
      type: t,
      // Clear fields that don't apply to the new type
      sourceIp:        t === "DNAT" ? "" : prev.sourceIp,
      sourcePort:      t !== "SNAT" ? "" : prev.sourcePort,
      destinationIp:   t !== "DNAT" ? "" : prev.destinationIp,
      destinationPort: t !== "DNAT" ? "" : prev.destinationPort,
      translatedPort:  t === "PAT"  ? "" : prev.translatedPort,
    }));
    setErrors({});
  }

  const pVal = Number(form.priority);
  const pColor = priorityColor(isNaN(pVal) ? 0 : pVal);

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();

    const newErrors: FormErrors = {};
    if (!form.priority || isNaN(pVal) || !Number.isInteger(pVal) || pVal < 1 || pVal > 100) {
      newErrors.priority = "Integer 1–100 required";
    }
    const spErr = validatePort(form.sourcePort);
    const dpErr = validatePort(form.destinationPort);
    const npErr = validatePort(form.translatedPort);
    if (spErr) newErrors.sourcePort      = spErr;
    if (dpErr) newErrors.destinationPort = dpErr;
    if (npErr) newErrors.translatedPort  = npErr;

    if (Object.keys(newErrors).length > 0) {
      setErrors(newErrors);
      return;
    }

    const result: NatRule = {
      id:              rule?.id ?? crypto.randomUUID(),
      type:            form.type,
      isActive:        form.isActive,
      priority:        pVal,
      sourceIp:        form.sourceIp.trim()       || null,
      sourcePort:      toNullableInt(form.sourcePort),
      destinationIp:   form.destinationIp.trim()  || null,
      destinationPort: toNullableInt(form.destinationPort),
      translatedIp:    form.translatedIp.trim()   || null,
      translatedPort:  toNullableInt(form.translatedPort),
      createdAt:  rule?.createdAt ?? new Date().toISOString(),
      updatedAt:  new Date().toISOString(),
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
        className="fixed inset-y-0 right-0 z-50 w-[500px] max-w-full bg-[#161616] border-l border-[#262626] flex flex-col transition-transform duration-200 ease-in-out"
        style={{ transform: isOpen ? "translateX(0)" : "translateX(100%)" }}
        role="dialog"
        aria-modal="true"
        aria-label={isEditMode ? "Edit NAT rule" : "New NAT rule"}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#262626] flex-shrink-0">
          <div>
            <div className="text-[9px] text-[#4a4a4a] tracking-[0.4em] uppercase mb-0.5">
              {isEditMode ? "Editing" : "Creating"}
            </div>
            <div className="text-[13px] tracking-[0.3em] uppercase text-[#f5f5f5]">
              {isEditMode ? "Edit NAT Rule" : "New NAT Rule"}
            </div>
            {isEditMode ? (
              <div className="text-[10px] text-[#06b6d4] font-mono mt-0.5 tracking-wider">
                {rule.id.slice(0, 8)}…
              </div>
            ) : null}
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
        <form onSubmit={handleSubmit} className="flex-1 overflow-y-auto px-6 py-5 space-y-5">

          {/* Type selector */}
          <div className="flex flex-col gap-2">
            <label className="text-[9px] uppercase tracking-[0.2em] text-[#8a8a8a]">
              Rule Type <span className="text-[#f43f5e]">*</span>
            </label>
            <TypeToggle value={form.type} onChange={handleTypeChange} />
            <p className="text-[9px] text-[#4a4a4a] leading-relaxed">
              {TYPE_HINTS[form.type]}
            </p>
          </div>

          {/* Priority */}
          <div className="flex flex-col gap-1.5">
            <label className="text-[9px] uppercase tracking-[0.2em] text-[#8a8a8a]">
              Priority <span className="text-[#f43f5e]">*</span>
              <span className="text-[#4a4a4a] ml-2 normal-case tracking-normal text-[8px]">
                (1 = highest, 100 = lowest)
              </span>
            </label>
            <div className="flex items-center gap-3">
              <input
                className="input text-sm w-20 flex-shrink-0"
                type="number"
                min={1}
                max={100}
                value={form.priority}
                onChange={(e) => setField("priority", e.target.value)}
              />
              <div className="flex-1 h-[3px] bg-[#262626] relative overflow-hidden">
                <div
                  className="absolute inset-y-0 left-0 transition-all duration-150"
                  style={{
                    width: `${Math.min(100, Math.max(0, pVal || 0))}%`,
                    backgroundColor: pColor,
                  }}
                />
              </div>
            </div>
            {errors.priority !== undefined ? (
              <p className="text-[10px] text-[#f43f5e] tracking-wider">{errors.priority}</p>
            ) : null}
          </div>

          {/* Active toggle */}
          <div className="flex items-center justify-between py-3 border-t border-b border-[#262626]">
            <div>
              <div className="text-[10px] text-[#8a8a8a] uppercase tracking-[0.25em]">Active</div>
              <div className="text-[10px] text-[#4a4a4a] mt-0.5">
                Rule is enforced immediately when active
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
                style={{ transform: form.isActive ? "translateX(18px)" : "translateX(2px)" }}
              />
            </button>
          </div>

          {/* ── SNAT fields: Source IP+Port → Translated IP+Port ── */}
          {form.type === "SNAT" ? (
            <>
              <div>
                <SectionLabel>Source (Original)</SectionLabel>
                <div className="grid grid-cols-2 gap-3">
                  <FieldGroup label="IP Address" optional>
                    <input
                      className="input text-sm font-mono"
                      type="text"
                      value={form.sourceIp}
                      onChange={(e) => setField("sourceIp", e.target.value)}
                      placeholder="192.168.1.0/24"
                      autoComplete="off"
                    />
                  </FieldGroup>
                  <FieldGroup label="Port" optional error={errors.sourcePort}>
                    <input
                      className={`input text-sm font-mono ${errors.sourcePort !== undefined ? "border-[#f43f5e]" : ""}`}
                      type="number"
                      min={1}
                      max={65535}
                      value={form.sourcePort}
                      onChange={(e) => setField("sourcePort", e.target.value)}
                      placeholder="e.g. 443"
                    />
                  </FieldGroup>
                </div>
              </div>
              <div>
                <SectionLabel>Translated (After SNAT)</SectionLabel>
                <div className="grid grid-cols-2 gap-3">
                  <FieldGroup label="IP Address" optional>
                    <input
                      className="input text-sm font-mono"
                      type="text"
                      value={form.translatedIp}
                      onChange={(e) => setField("translatedIp", e.target.value)}
                      placeholder="203.0.113.10"
                      autoComplete="off"
                    />
                  </FieldGroup>
                  <FieldGroup label="Port" optional error={errors.translatedPort}>
                    <input
                      className={`input text-sm font-mono ${errors.translatedPort !== undefined ? "border-[#f43f5e]" : ""}`}
                      type="number"
                      min={1}
                      max={65535}
                      value={form.translatedPort}
                      onChange={(e) => setField("translatedPort", e.target.value)}
                      placeholder="e.g. 8443"
                    />
                  </FieldGroup>
                </div>
              </div>
            </>
          ) : null}

          {/* ── DNAT fields: Destination IP+Port → Translated IP+Port ── */}
          {form.type === "DNAT" ? (
            <>
              <div>
                <SectionLabel>Destination (Original)</SectionLabel>
                <div className="grid grid-cols-2 gap-3">
                  <FieldGroup label="IP Address" optional>
                    <input
                      className="input text-sm font-mono"
                      type="text"
                      value={form.destinationIp}
                      onChange={(e) => setField("destinationIp", e.target.value)}
                      placeholder="203.0.113.10"
                      autoComplete="off"
                    />
                  </FieldGroup>
                  <FieldGroup label="Port" optional error={errors.destinationPort}>
                    <input
                      className={`input text-sm font-mono ${errors.destinationPort !== undefined ? "border-[#f43f5e]" : ""}`}
                      type="number"
                      min={1}
                      max={65535}
                      value={form.destinationPort}
                      onChange={(e) => setField("destinationPort", e.target.value)}
                      placeholder="e.g. 443"
                    />
                  </FieldGroup>
                </div>
              </div>
              <div>
                <SectionLabel>Redirect To (Internal Server)</SectionLabel>
                <div className="grid grid-cols-2 gap-3">
                  <FieldGroup label="IP Address" optional>
                    <input
                      className="input text-sm font-mono"
                      type="text"
                      value={form.translatedIp}
                      onChange={(e) => setField("translatedIp", e.target.value)}
                      placeholder="10.0.0.5"
                      autoComplete="off"
                    />
                  </FieldGroup>
                  <FieldGroup label="Port" optional error={errors.translatedPort}>
                    <input
                      className={`input text-sm font-mono ${errors.translatedPort !== undefined ? "border-[#f43f5e]" : ""}`}
                      type="number"
                      min={1}
                      max={65535}
                      value={form.translatedPort}
                      onChange={(e) => setField("translatedPort", e.target.value)}
                      placeholder="e.g. 8080"
                    />
                  </FieldGroup>
                </div>
              </div>
            </>
          ) : null}

          {/* ── PAT fields: Source IP Range → Translated Public IP (no ports) ── */}
          {form.type === "PAT" ? (
            <>
              <div>
                <SectionLabel>Source Range (Private Network)</SectionLabel>
                <FieldGroup label="IP Range" optional>
                  <input
                    className="input text-sm font-mono"
                    type="text"
                    value={form.sourceIp}
                    onChange={(e) => setField("sourceIp", e.target.value)}
                    placeholder="e.g. 10.0.0.0/8"
                    autoComplete="off"
                  />
                </FieldGroup>
              </div>
              <div>
                <SectionLabel>Translated (Single Public IP)</SectionLabel>
                <FieldGroup label="IP Address" optional>
                  <input
                    className="input text-sm font-mono"
                    type="text"
                    value={form.translatedIp}
                    onChange={(e) => setField("translatedIp", e.target.value)}
                    placeholder="e.g. 203.0.113.1"
                    autoComplete="off"
                  />
                </FieldGroup>
              </div>
            </>
          ) : null}

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
            {isEditMode ? "Save Changes" : "Create Rule"}
          </button>
        </div>
      </div>
    </>
  );
}
