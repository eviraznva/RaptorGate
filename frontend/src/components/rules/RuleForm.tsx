import { useEffect, useState } from "react";
import type { Rule } from "../../types/rules/Rules";
import type { ApiSuccess } from "../../types/ApiResponse";
import {
  useCreateRuleMutation,
  useUpdateRuleMutation,
  type CreateRuleBody,
} from "../../services/rules";

interface RuleFormProps {
  rule: Rule | null;
  isOpen: boolean;
  onClose: () => void;
  onSuccess: (rule: Rule, mode: "create" | "edit") => void;
}

interface FormState {
  name: string;
  priority: string;
  zonePairId: string;
  content: string;
  description: string;
  isActive: boolean;
}

interface FormErrors {
  name?: string;
  priority?: string;
  zonePairId?: string;
  content?: string;
}

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const EMPTY: FormState = {
  name: "",
  priority: "10",
  zonePairId: "",
  content: "",
  description: "",
  isActive: true,
};

function fromRule(r: Rule): FormState {
  return {
    name: r.name,
    priority: String(r.priority),
    zonePairId: r.zonePairId,
    content: r.content,
    description: r.description ?? "",
    isActive: r.isActive,
  };
}

function validate(f: FormState): FormErrors {
  const e: FormErrors = {};
  if (!f.name.trim()) e.name = "Required";
  else if (f.name.length > 128) e.name = "Max 128 chars";
  const p = Number(f.priority);
  if (!f.priority || isNaN(p) || !Number.isInteger(p) || p < 1 || p > 100)
    e.priority = "Integer 1–100";
  if (!f.zonePairId.trim()) e.zonePairId = "Required";
  else if (!UUID_RE.test(f.zonePairId.trim())) e.zonePairId = "Invalid UUID";
  if (!f.content.trim()) e.content = "Required";
  return e;
}

export function RuleForm({ rule, isOpen, onClose, onSuccess }: RuleFormProps) {
  const isEditMode = rule !== null;
  const [form, setForm] = useState<FormState>(EMPTY);
  const [errors, setErrors] = useState<FormErrors>({});
  const [submitError, setSubmitError] = useState<string | null>(null);

  const [createRule, { isLoading: creating }] = useCreateRuleMutation();
  const [updateRule, { isLoading: updating }] = useUpdateRuleMutation();
  const isSubmitting = creating || updating;

  useEffect(() => {
    if (isOpen) {
      setForm(rule ? fromRule(rule) : EMPTY);
      setErrors({});
      setSubmitError(null);
    }
  }, [isOpen, rule]);

  function setField<K extends keyof FormState>(key: K, value: FormState[K]) {
    setForm((prev) => ({ ...prev, [key]: value }));
    if (errors[key as keyof FormErrors]) {
      setErrors((prev) => ({ ...prev, [key]: undefined }));
    }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const errs = validate(form);
    if (Object.keys(errs).length > 0) {
      setErrors(errs);
      return;
    }
    setSubmitError(null);

    const body: CreateRuleBody = {
      name: form.name.trim(),
      description: form.description.trim() || undefined,
      zonePairId: form.zonePairId.trim(),
      isActive: form.isActive,
      content: form.content.trim(),
      priority: Number(form.priority),
    };

    try {
      if (isEditMode) {
        const result = await updateRule({ id: rule.id, ...body });
        if ("error" in result) {
          const err = result.error as { data?: { message?: string } };
          setSubmitError(err?.data?.message ?? "Update failed");
          return;
        }
        const payload = result.data as ApiSuccess<Rule>;
        onSuccess(payload.data, "edit");
      } else {
        const result = await createRule(body);
        if ("error" in result) {
          const err = result.error as { data?: { message?: string } };
          setSubmitError(err?.data?.message ?? "Create failed");
          return;
        }
        const payload = result.data as ApiSuccess<{ rule: Rule }>;
        onSuccess(payload.data.rule, "create");
      }
    } catch {
      setSubmitError("Unexpected error");
    }
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
        aria-label={isEditMode ? "Edit rule" : "New rule"}
      >
        {/* Drawer header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#262626] flex-shrink-0">
          <div>
            <div className="text-[9px] text-[#4a4a4a] tracking-[0.4em] uppercase mb-0.5">
              {isEditMode ? "Editing" : "Creating"}
            </div>
            <div className="text-[13px] tracking-[0.3em] uppercase text-[#f5f5f5]">
              {isEditMode ? "Edit Rule" : "New Rule"}
            </div>
            {isEditMode && (
              <div className="text-[10px] text-[#06b6d4] font-mono mt-0.5 tracking-wider">
                {rule.name}
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

        {/* Form body */}
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
              placeholder="Allow HTTPS"
              maxLength={128}
              autoComplete="off"
            />
            {errors.name && (
              <p className="text-[10px] text-[#f43f5e] mt-1 tracking-wider">
                {errors.name}
              </p>
            )}
          </div>

          {/* Priority */}
          <div>
            <label className="block text-[10px] text-[#8a8a8a] uppercase tracking-[0.25em] mb-1.5">
              Priority <span className="text-[#f43f5e]">*</span>
              <span className="text-[#4a4a4a] ml-2 normal-case tracking-normal">
                (1 = highest, 100 = lowest)
              </span>
            </label>
            <div className="flex items-center gap-3">
              <input
                className="input text-sm w-24"
                type="number"
                min={1}
                max={100}
                value={form.priority}
                onChange={(e) => setField("priority", e.target.value)}
              />
              <div className="flex-1 h-1 bg-[#262626] relative overflow-hidden">
                <div
                  className="absolute inset-y-0 left-0 transition-all duration-150"
                  style={{
                    width: `${Math.min(100, Math.max(0, Number(form.priority) || 0))}%`,
                    background: (() => {
                      const p = Number(form.priority) || 0;
                      return p <= 3
                        ? "#f43f5e"
                        : p <= 7
                          ? "#f59e0b"
                          : "#06b6d4";
                    })(),
                  }}
                />
              </div>
            </div>
            {errors.priority && (
              <p className="text-[10px] text-[#f43f5e] mt-1 tracking-wider">
                {errors.priority}
              </p>
            )}
          </div>

          {/* Zone Pair ID */}
          <div>
            <label className="block text-[10px] text-[#8a8a8a] uppercase tracking-[0.25em] mb-1.5">
              Zone Pair ID <span className="text-[#f43f5e]">*</span>
            </label>
            <input
              className="input text-sm font-mono"
              type="text"
              value={form.zonePairId}
              onChange={(e) => setField("zonePairId", e.target.value)}
              placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
              spellCheck={false}
            />
            {errors.zonePairId ? (
              <p className="text-[10px] text-[#f43f5e] mt-1 tracking-wider">
                {errors.zonePairId}
              </p>
            ) : (
              form.zonePairId && UUID_RE.test(form.zonePairId.trim()) && (
                <p className="text-[10px] text-[#10b981] mt-1 tracking-wider">
                  Valid UUID
                </p>
              )
            )}
          </div>

          {/* Content */}
          <div>
            <label className="block text-[10px] text-[#8a8a8a] uppercase tracking-[0.25em] mb-1.5">
              Rule Content <span className="text-[#f43f5e]">*</span>
            </label>
            <textarea
              className="input text-sm font-mono resize-none leading-relaxed"
              rows={5}
              value={form.content}
              onChange={(e) => setField("content", e.target.value)}
              placeholder={"allow tcp any any eq 443"}
              spellCheck={false}
            />
            {errors.content && (
              <p className="text-[10px] text-[#f43f5e] mt-1 tracking-wider">
                {errors.content}
              </p>
            )}
          </div>

          {/* Description */}
          <div>
            <label className="block text-[10px] text-[#8a8a8a] uppercase tracking-[0.25em] mb-1.5">
              Description
              <span className="text-[#4a4a4a] ml-2 normal-case tracking-normal">
                optional
              </span>
            </label>
            <textarea
              className="input text-sm resize-none"
              rows={2}
              value={form.description}
              onChange={(e) => setField("description", e.target.value)}
              placeholder="Allow outgoing HTTPS traffic to external APIs"
            />
          </div>

          {/* Is Active toggle */}
          <div className="flex items-center justify-between py-3 border-t border-[#262626]">
            <div>
              <div className="text-[10px] text-[#8a8a8a] uppercase tracking-[0.25em]">
                Active
              </div>
              <div className="text-[10px] text-[#4a4a4a] mt-0.5">
                Rule will be enforced immediately
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

          {/* Submit error */}
          {submitError !== null && (
            <div className="border border-[#f43f5e]/30 bg-[#f43f5e]/8 px-4 py-3 text-[11px] text-[#f43f5e] tracking-wider">
              ⚠ {submitError}
            </div>
          )}
        </form>

        {/* Drawer footer */}
        <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-[#262626] flex-shrink-0">
          <button
            type="button"
            onClick={onClose}
            disabled={isSubmitting}
            className="px-5 py-2 text-[10px] uppercase tracking-[0.25em] text-[#8a8a8a] hover:text-[#f5f5f5] border border-[#262626] hover:border-[#4a4a4a] transition-colors disabled:opacity-40"
          >
            Cancel
          </button>
          <button
            type="submit"
            form=""
            onClick={handleSubmit}
            disabled={isSubmitting}
            className="btn-primary px-5 py-2 text-[10px] uppercase tracking-[0.25em] disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {isSubmitting
              ? isEditMode
                ? "Saving…"
                : "Creating…"
              : isEditMode
                ? "Save Changes"
                : "Create Rule"}
          </button>
        </div>
      </div>
    </>
  );
}
