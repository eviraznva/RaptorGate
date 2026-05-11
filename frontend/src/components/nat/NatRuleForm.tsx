import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import type {
  NatProtocolName,
  NatRule,
  NatRuleUpsertBody,
  NatType,
} from "../../types/nat/NatRule";
import { getNatRuleType } from "../../types/nat/NatRule";

type NatRuleFormProps = {
  rule: NatRule | null;
  isOpen: boolean;
  onClose: () => void;
  onSuccess: (body: NatRuleUpsertBody, mode: "create" | "edit", id?: string) => void;
};

interface FormState {
  type: NatType;
  protocol: NatProtocolName;
  isActive: boolean;
  priority: string;
  inInterface: string;
  outInterface: string;
  inZone: string;
  outZone: string;
  matchSrcPortMin: string;
  matchSrcPortMax: string;
  matchDstPortMin: string;
  matchDstPortMax: string;
  srcCidr: string;
  srcPortMin: string;
  srcPortMax: string;
  dstCidr: string;
  dstIp: string;
  dstPort: string;
  translatedIp: string;
  translatedPort: string;
}

type FormErrors = Partial<Record<keyof FormState, string>>;

const EMPTY: FormState = {
  type: "SNAT",
  protocol: "NAT_PROTOCOL_ALL",
  isActive: true,
  priority: "10",
  inInterface: "",
  outInterface: "",
  inZone: "",
  outZone: "",
  matchSrcPortMin: "",
  matchSrcPortMax: "",
  matchDstPortMin: "",
  matchDstPortMax: "",
  srcCidr: "",
  srcPortMin: "",
  srcPortMax: "",
  dstCidr: "",
  dstIp: "",
  dstPort: "",
  translatedIp: "",
  translatedPort: "",
};

const TYPE_HINTS: Record<NatType, string> = {
  SNAT: "Source NAT — rewrites source address of matching packets.",
  DNAT: "Destination NAT — rewrites destination address of matching packets.",
  PAT: "Port Address Translation — rewrites destination IP and port.",
  MASQUERADE: "Masquerade — rewrites source address dynamically on egress.",
};

const TYPE_ACTIVE_STYLES: Record<NatType, string> = {
  SNAT: "text-[#06b6d4] border-[#06b6d4]/40 bg-[#06b6d4]/12",
  DNAT: "text-[#f59e0b] border-[#f59e0b]/40 bg-[#f59e0b]/12",
  PAT: "text-[#10b981] border-[#10b981]/40 bg-[#10b981]/12",
  MASQUERADE: "text-[#a855f7] border-[#a855f7]/40 bg-[#a855f7]/12",
};

const NAT_TYPES: NatType[] = ["SNAT", "DNAT", "PAT", "MASQUERADE"];

function protocolName(protocol: NatRule["protocol"]): NatProtocolName {
  switch (protocol) {
    case 1:
    case "NAT_PROTOCOL_TCP":
      return "NAT_PROTOCOL_TCP";
    case 2:
    case "NAT_PROTOCOL_UDP":
      return "NAT_PROTOCOL_UDP";
    case 3:
    case "NAT_PROTOCOL_ICMP":
      return "NAT_PROTOCOL_ICMP";
    default:
      return "NAT_PROTOCOL_ALL";
  }
}

function fromRule(r: NatRule): FormState {
  const state: FormState = {
    ...EMPTY,
    type: getNatRuleType(r),
    protocol: protocolName(r.protocol),
    isActive: r.isActive,
    priority: String(r.priority),
    inInterface: r.inInterface ?? "",
    outInterface: r.outInterface ?? "",
    inZone: r.inZone ?? "",
    outZone: r.outZone ?? "",
    matchSrcPortMin: r.matchSrcPortMin !== null ? String(r.matchSrcPortMin) : "",
    matchSrcPortMax: r.matchSrcPortMax !== null ? String(r.matchSrcPortMax) : "",
    matchDstPortMin: r.matchDstPortMin !== null ? String(r.matchDstPortMin) : "",
    matchDstPortMax: r.matchDstPortMax !== null ? String(r.matchDstPortMax) : "",
  };

  switch (r.action.$case) {
    case "snat":
      return {
        ...state,
        srcCidr: r.action.snat.srcCidr,
        translatedIp: r.action.snat.translatedIp,
        srcPortMin: r.action.snat.srcPortMin != null ? String(r.action.snat.srcPortMin) : "",
        srcPortMax: r.action.snat.srcPortMax != null ? String(r.action.snat.srcPortMax) : "",
      };
    case "dnat":
      return {
        ...state,
        dstCidr: r.action.dnat.dstCidr,
        translatedIp: r.action.dnat.translatedIp,
        translatedPort: r.action.dnat.translatedPort != null ? String(r.action.dnat.translatedPort) : "",
      };
    case "pat":
      return {
        ...state,
        dstIp: r.action.pat.dstIp,
        dstPort: String(r.action.pat.dstPort),
        translatedIp: r.action.pat.translatedIp,
        translatedPort: String(r.action.pat.translatedPort),
      };
    case "masquerade":
      return {
        ...state,
        srcCidr: r.action.masquerade.srcCidr ?? "",
        srcPortMin: r.action.masquerade.srcPortMin != null ? String(r.action.masquerade.srcPortMin) : "",
        srcPortMax: r.action.masquerade.srcPortMax != null ? String(r.action.masquerade.srcPortMax) : "",
      };
  }
}

function validatePort(val: string): string | undefined {
  if (val === "") return undefined;
  const n = Number(val);
  if (!Number.isInteger(n) || n < 1 || n > 65535) return "Must be 1–65535";
  return undefined;
}

function validateRequired(val: string): string | undefined {
  return val.trim() === "" ? "Required" : undefined;
}

function toNullableText(val: string): string | null {
  const trimmed = val.trim();
  return trimmed === "" ? null : trimmed;
}

function toOptionalInt(val: string): number | null {
  if (val === "") return null;
  return Number(val);
}

function priorityColor(p: number) {
  return p <= 3 ? "#f43f5e" : p <= 7 ? "#f59e0b" : "#06b6d4";
}

function TypeToggle({ value, onChange }: { value: NatType; onChange: (t: NatType) => void }) {
  return (
    <div className="grid grid-cols-4">
      {NAT_TYPES.map((t, i) => (
        <button
          key={t}
          type="button"
          onClick={() => onChange(t)}
          className={`py-2.5 text-[10px] uppercase tracking-[0.15em] border transition-colors
            ${i > 0 ? "border-l-0" : ""}
            ${
              value === t
                ? TYPE_ACTIVE_STYLES[t]
                : "text-[#4a4a4a] border-[#262626] hover:text-[#f5f5f5] hover:border-[#4a4a4a]"
            }`}
        >
          {t === "MASQUERADE" ? "MASQ" : t}
        </button>
      ))}
    </div>
  );
}

function SectionLabel({ children }: { children: ReactNode }) {
  return (
    <div className="text-[9px] uppercase text-[#4a4a4a] border-b border-[#262626] pb-1.5 mb-3 tracking-[0.25em]">
      {children}
    </div>
  );
}

function FieldGroup({
  label,
  optional,
  error,
  children,
}: {
  label: string;
  optional?: boolean;
  error?: string;
  children: ReactNode;
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
    if (!isOpen) return;
    setForm(rule ? fromRule(rule) : EMPTY);
    setErrors({});
  }, [isOpen, rule]);

  function setField<K extends keyof FormState>(key: K, value: FormState[K]) {
    setForm((prev) => ({ ...prev, [key]: value }));
    if (key in errors) {
      setErrors((prev) => ({ ...prev, [key]: undefined }));
    }
  }

  function handleTypeChange(type: NatType) {
    setForm((prev) => ({
      ...prev,
      type,
      srcCidr: "",
      srcPortMin: "",
      srcPortMax: "",
      dstCidr: "",
      dstIp: "",
      dstPort: "",
      translatedIp: "",
      translatedPort: "",
    }));
    setErrors({});
  }

  function buildAction(): NatRuleUpsertBody["action"] {
    switch (form.type) {
      case "SNAT":
        return {
          $case: "snat",
          snat: {
            srcCidr: form.srcCidr.trim(),
            translatedIp: form.translatedIp.trim(),
            srcPortMin: toOptionalInt(form.srcPortMin),
            srcPortMax: toOptionalInt(form.srcPortMax),
          },
        };
      case "DNAT":
        return {
          $case: "dnat",
          dnat: {
            dstCidr: form.dstCidr.trim(),
            translatedIp: form.translatedIp.trim(),
            translatedPort: toOptionalInt(form.translatedPort),
          },
        };
      case "PAT":
        return {
          $case: "pat",
          pat: {
            dstIp: form.dstIp.trim(),
            dstPort: Number(form.dstPort),
            translatedIp: form.translatedIp.trim(),
            translatedPort: Number(form.translatedPort),
          },
        };
      case "MASQUERADE":
        return {
          $case: "masquerade",
          masquerade: {
            srcCidr: toNullableText(form.srcCidr),
            srcPortMin: toOptionalInt(form.srcPortMin),
            srcPortMax: toOptionalInt(form.srcPortMax),
          },
        };
    }
  }

  function validate(): FormErrors {
    const newErrors: FormErrors = {};
    const priority = Number(form.priority);

    if (!form.priority || !Number.isInteger(priority) || priority < 1 || priority > 100) {
      newErrors.priority = "Integer 1–100 required";
    }

    ([
      "matchSrcPortMin",
      "matchSrcPortMax",
      "matchDstPortMin",
      "matchDstPortMax",
      "srcPortMin",
      "srcPortMax",
      "dstPort",
      "translatedPort",
    ] as const).forEach((key) => {
      const error = validatePort(form[key]);
      if (error) newErrors[key] = error;
    });

    if (form.type === "SNAT") {
      newErrors.srcCidr = validateRequired(form.srcCidr);
      newErrors.translatedIp = validateRequired(form.translatedIp);
    }

    if (form.type === "DNAT") {
      newErrors.dstCidr = validateRequired(form.dstCidr);
      newErrors.translatedIp = validateRequired(form.translatedIp);
      if (form.translatedPort !== "") {
        newErrors.translatedPort = validatePort(form.translatedPort);
      }
    }

    if (form.type === "PAT") {
      newErrors.dstIp = validateRequired(form.dstIp);
      newErrors.dstPort = newErrors.dstPort ?? validateRequired(form.dstPort);
      newErrors.translatedIp = validateRequired(form.translatedIp);
      newErrors.translatedPort = newErrors.translatedPort ?? validateRequired(form.translatedPort);
    }

    Object.keys(newErrors).forEach((key) => {
      if (newErrors[key as keyof FormErrors] === undefined) {
        delete newErrors[key as keyof FormErrors];
      }
    });

    return newErrors;
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault();

    const newErrors = validate();
    if (Object.keys(newErrors).length > 0) {
      setErrors(newErrors);
      return;
    }

    const body: NatRuleUpsertBody = {
      isActive: form.isActive,
      priority: Number(form.priority),
      protocol: form.protocol,
      inInterface: toNullableText(form.inInterface),
      outInterface: toNullableText(form.outInterface),
      inZone: toNullableText(form.inZone),
      outZone: toNullableText(form.outZone),
      matchSrcPortMin: toOptionalInt(form.matchSrcPortMin),
      matchSrcPortMax: toOptionalInt(form.matchSrcPortMax),
      matchDstPortMin: toOptionalInt(form.matchDstPortMin),
      matchDstPortMax: toOptionalInt(form.matchDstPortMax),
      action: buildAction(),
    };

    onSuccess(body, isEditMode ? "edit" : "create", rule?.id);
  }

  const pVal = Number(form.priority);
  const pColor = priorityColor(Number.isNaN(pVal) ? 0 : pVal);

  return (
    <>
      <div
        className="fixed inset-0 z-40 bg-black/70 transition-opacity duration-200"
        style={{ opacity: isOpen ? 1 : 0, pointerEvents: isOpen ? "auto" : "none" }}
        onClick={onClose}
        aria-hidden="true"
      />

      <div
        className="fixed inset-y-0 right-0 z-50 w-[560px] max-w-full bg-[#161616] border-l border-[#262626] flex flex-col transition-transform duration-200 ease-in-out"
        style={{ transform: isOpen ? "translateX(0)" : "translateX(100%)" }}
        role="dialog"
        aria-modal="true"
        aria-label={isEditMode ? "Edit NAT rule" : "New NAT rule"}
      >
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

        <form onSubmit={handleSubmit} className="flex-1 min-h-0 flex flex-col">
          <div className="flex-1 overflow-y-auto px-6 py-5 space-y-5">
            <div className="flex flex-col gap-2">
              <label className="text-[9px] uppercase tracking-[0.2em] text-[#8a8a8a]">
                Action Type <span className="text-[#f43f5e]">*</span>
              </label>
              <TypeToggle value={form.type} onChange={handleTypeChange} />
              <p className="text-[9px] text-[#4a4a4a] leading-relaxed">
                {TYPE_HINTS[form.type]}
              </p>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <FieldGroup label="Protocol">
                <select
                  className="input text-sm"
                  value={form.protocol}
                  onChange={(e) => setField("protocol", e.target.value as NatProtocolName)}
                >
                  <option value="NAT_PROTOCOL_ALL">ALL</option>
                  <option value="NAT_PROTOCOL_TCP">TCP</option>
                  <option value="NAT_PROTOCOL_UDP">UDP</option>
                  <option value="NAT_PROTOCOL_ICMP">ICMP</option>
                </select>
              </FieldGroup>
              <FieldGroup label="Priority" error={errors.priority}>
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
              </FieldGroup>
            </div>

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

            <div>
              <SectionLabel>Scope</SectionLabel>
              <div className="grid grid-cols-2 gap-3">
                <FieldGroup label="In Interface" optional>
                  <input className="input text-sm font-mono" value={form.inInterface} onChange={(e) => setField("inInterface", e.target.value)} placeholder="lan0" autoComplete="off" />
                </FieldGroup>
                <FieldGroup label="Out Interface" optional>
                  <input className="input text-sm font-mono" value={form.outInterface} onChange={(e) => setField("outInterface", e.target.value)} placeholder="wan0" autoComplete="off" />
                </FieldGroup>
                <FieldGroup label="In Zone" optional>
                  <input className="input text-sm font-mono" value={form.inZone} onChange={(e) => setField("inZone", e.target.value)} placeholder="lan" autoComplete="off" />
                </FieldGroup>
                <FieldGroup label="Out Zone" optional>
                  <input className="input text-sm font-mono" value={form.outZone} onChange={(e) => setField("outZone", e.target.value)} placeholder="wan" autoComplete="off" />
                </FieldGroup>
              </div>
            </div>

            <div>
              <SectionLabel>Port Match</SectionLabel>
              <div className="grid grid-cols-4 gap-3">
                <FieldGroup label="Src Min" optional error={errors.matchSrcPortMin}>
                  <input className={`input text-sm font-mono ${errors.matchSrcPortMin ? "border-[#f43f5e]" : ""}`} type="number" min={1} max={65535} value={form.matchSrcPortMin} onChange={(e) => setField("matchSrcPortMin", e.target.value)} placeholder="1024" />
                </FieldGroup>
                <FieldGroup label="Src Max" optional error={errors.matchSrcPortMax}>
                  <input className={`input text-sm font-mono ${errors.matchSrcPortMax ? "border-[#f43f5e]" : ""}`} type="number" min={1} max={65535} value={form.matchSrcPortMax} onChange={(e) => setField("matchSrcPortMax", e.target.value)} placeholder="65535" />
                </FieldGroup>
                <FieldGroup label="Dst Min" optional error={errors.matchDstPortMin}>
                  <input className={`input text-sm font-mono ${errors.matchDstPortMin ? "border-[#f43f5e]" : ""}`} type="number" min={1} max={65535} value={form.matchDstPortMin} onChange={(e) => setField("matchDstPortMin", e.target.value)} placeholder="443" />
                </FieldGroup>
                <FieldGroup label="Dst Max" optional error={errors.matchDstPortMax}>
                  <input className={`input text-sm font-mono ${errors.matchDstPortMax ? "border-[#f43f5e]" : ""}`} type="number" min={1} max={65535} value={form.matchDstPortMax} onChange={(e) => setField("matchDstPortMax", e.target.value)} placeholder="443" />
                </FieldGroup>
              </div>
            </div>

            {form.type === "SNAT" ? (
              <div>
                <SectionLabel>SNAT Action</SectionLabel>
                <div className="grid grid-cols-2 gap-3">
                  <FieldGroup label="Source CIDR" error={errors.srcCidr}>
                    <input className={`input text-sm font-mono ${errors.srcCidr ? "border-[#f43f5e]" : ""}`} value={form.srcCidr} onChange={(e) => setField("srcCidr", e.target.value)} placeholder="192.168.1.0/24" autoComplete="off" />
                  </FieldGroup>
                  <FieldGroup label="Translated IP" error={errors.translatedIp}>
                    <input className={`input text-sm font-mono ${errors.translatedIp ? "border-[#f43f5e]" : ""}`} value={form.translatedIp} onChange={(e) => setField("translatedIp", e.target.value)} placeholder="203.0.113.10" autoComplete="off" />
                  </FieldGroup>
                  <FieldGroup label="Source Port Min" optional error={errors.srcPortMin}>
                    <input className={`input text-sm font-mono ${errors.srcPortMin ? "border-[#f43f5e]" : ""}`} type="number" min={1} max={65535} value={form.srcPortMin} onChange={(e) => setField("srcPortMin", e.target.value)} placeholder="1024" />
                  </FieldGroup>
                  <FieldGroup label="Source Port Max" optional error={errors.srcPortMax}>
                    <input className={`input text-sm font-mono ${errors.srcPortMax ? "border-[#f43f5e]" : ""}`} type="number" min={1} max={65535} value={form.srcPortMax} onChange={(e) => setField("srcPortMax", e.target.value)} placeholder="65535" />
                  </FieldGroup>
                </div>
              </div>
            ) : null}

            {form.type === "DNAT" ? (
              <div>
                <SectionLabel>DNAT Action</SectionLabel>
                <div className="grid grid-cols-2 gap-3">
                  <FieldGroup label="Destination CIDR" error={errors.dstCidr}>
                    <input className={`input text-sm font-mono ${errors.dstCidr ? "border-[#f43f5e]" : ""}`} value={form.dstCidr} onChange={(e) => setField("dstCidr", e.target.value)} placeholder="203.0.113.10/32" autoComplete="off" />
                  </FieldGroup>
                  <FieldGroup label="Translated IP" error={errors.translatedIp}>
                    <input className={`input text-sm font-mono ${errors.translatedIp ? "border-[#f43f5e]" : ""}`} value={form.translatedIp} onChange={(e) => setField("translatedIp", e.target.value)} placeholder="10.0.0.10" autoComplete="off" />
                  </FieldGroup>
                  <FieldGroup label="Translated Port" optional error={errors.translatedPort}>
                    <input className={`input text-sm font-mono ${errors.translatedPort ? "border-[#f43f5e]" : ""}`} type="number" min={1} max={65535} value={form.translatedPort} onChange={(e) => setField("translatedPort", e.target.value)} placeholder="80" />
                  </FieldGroup>
                </div>
              </div>
            ) : null}

            {form.type === "PAT" ? (
              <div>
                <SectionLabel>PAT Action</SectionLabel>
                <div className="grid grid-cols-2 gap-3">
                  <FieldGroup label="Destination IP" error={errors.dstIp}>
                    <input className={`input text-sm font-mono ${errors.dstIp ? "border-[#f43f5e]" : ""}`} value={form.dstIp} onChange={(e) => setField("dstIp", e.target.value)} placeholder="203.0.113.10" autoComplete="off" />
                  </FieldGroup>
                  <FieldGroup label="Destination Port" error={errors.dstPort}>
                    <input className={`input text-sm font-mono ${errors.dstPort ? "border-[#f43f5e]" : ""}`} type="number" min={1} max={65535} value={form.dstPort} onChange={(e) => setField("dstPort", e.target.value)} placeholder="443" />
                  </FieldGroup>
                  <FieldGroup label="Translated IP" error={errors.translatedIp}>
                    <input className={`input text-sm font-mono ${errors.translatedIp ? "border-[#f43f5e]" : ""}`} value={form.translatedIp} onChange={(e) => setField("translatedIp", e.target.value)} placeholder="10.0.0.10" autoComplete="off" />
                  </FieldGroup>
                  <FieldGroup label="Translated Port" error={errors.translatedPort}>
                    <input className={`input text-sm font-mono ${errors.translatedPort ? "border-[#f43f5e]" : ""}`} type="number" min={1} max={65535} value={form.translatedPort} onChange={(e) => setField("translatedPort", e.target.value)} placeholder="8443" />
                  </FieldGroup>
                </div>
              </div>
            ) : null}

            {form.type === "MASQUERADE" ? (
              <div>
                <SectionLabel>Masquerade Action</SectionLabel>
                <div className="grid grid-cols-3 gap-3">
                  <FieldGroup label="Source CIDR" optional>
                    <input className="input text-sm font-mono" value={form.srcCidr} onChange={(e) => setField("srcCidr", e.target.value)} placeholder="10.0.0.0/8" autoComplete="off" />
                  </FieldGroup>
                  <FieldGroup label="Source Port Min" optional error={errors.srcPortMin}>
                    <input className={`input text-sm font-mono ${errors.srcPortMin ? "border-[#f43f5e]" : ""}`} type="number" min={1} max={65535} value={form.srcPortMin} onChange={(e) => setField("srcPortMin", e.target.value)} placeholder="1024" />
                  </FieldGroup>
                  <FieldGroup label="Source Port Max" optional error={errors.srcPortMax}>
                    <input className={`input text-sm font-mono ${errors.srcPortMax ? "border-[#f43f5e]" : ""}`} type="number" min={1} max={65535} value={form.srcPortMax} onChange={(e) => setField("srcPortMax", e.target.value)} placeholder="65535" />
                  </FieldGroup>
                </div>
              </div>
            ) : null}
          </div>

          <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-[#262626] flex-shrink-0">
            <button
              type="button"
              onClick={onClose}
              className="px-5 py-2 text-[10px] uppercase tracking-[0.25em] text-[#8a8a8a] hover:text-[#f5f5f5] border border-[#262626] hover:border-[#4a4a4a] transition-colors"
            >
              Cancel
            </button>
            <button type="submit" className="btn-primary px-5 py-2 text-[10px] uppercase tracking-[0.25em]">
              {isEditMode ? "Save Changes" : "Create Rule"}
            </button>
          </div>
        </form>
      </div>
    </>
  );
}
