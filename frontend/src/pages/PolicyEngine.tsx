import { useCallback, useEffect, useState } from "react";
import { useAppDispatch, useAppSelector } from "../app/hooks";
import { RuleForm } from "../components/rules/RuleForm";
import {
  addRule,
  deleteRule,
  editRule,
  setRules,
} from "../features/rulesSlice";
import {
  useDeleteRuleMutation,
  useGetRulesQuery,
  type RulesPayload,
} from "../services/rules";
import type { Rule } from "../types/rules/Rules";
import type { ApiSuccess } from "../types/ApiResponse";

function PriorityBar({ priority }: { priority: number }) {
  const color =
    priority <= 3 ? "#f43f5e" : priority <= 7 ? "#f59e0b" : "#06b6d4";
  return (
    <div className="flex items-center gap-2.5">
      <div
        style={{ backgroundColor: color }}
        className="w-[2px] h-7 flex-shrink-0"
      />
      <span
        style={{ color }}
        className="font-mono text-sm font-bold tabular-nums w-5 text-right"
      >
        {priority}
      </span>
    </div>
  );
}

export default function PolicyEngine() {
  const dispatch = useAppDispatch();
  const rulesState = useAppSelector((state) => state.rules);
  const { data, isLoading, isError } = useGetRulesQuery();

  const [isFormOpen, setIsFormOpen] = useState(false);
  const [editingRule, setEditingRule] = useState<Rule | null>(null);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);

  const [doDeleteRule, { isLoading: isDeleting }] = useDeleteRuleMutation();

  useEffect(() => {
    if (!data) return;

    const payload = data as ApiSuccess<RulesPayload>;

    dispatch(setRules(payload.data.rules));
  }, [data, dispatch]);

  const handleOpenCreate = useCallback(() => {
    setEditingRule(null);
    setIsFormOpen(true);
  }, []);

  const handleOpenEdit = useCallback((rule: Rule) => {
    setEditingRule(rule);
    setIsFormOpen(true);
  }, []);

  const handleCloseForm = useCallback(() => setIsFormOpen(false), []);

  const handleFormSuccess = useCallback(
    (rule: Rule, mode: "create" | "edit") => {
      dispatch(mode === "create" ? addRule(rule) : editRule(rule));
      setIsFormOpen(false);
    },
    [dispatch],
  );

  const handleDeleteClick = useCallback(
    (id: string) => setConfirmDeleteId(id),
    [],
  );

  const handleDeleteCancel = useCallback(() => setConfirmDeleteId(null), []);

  const handleDeleteConfirm = useCallback(
    async (id: string) => {
      const result = await doDeleteRule(id);

      if (!("error" in result)) dispatch(deleteRule(id));
      setConfirmDeleteId(null);
    },
    [doDeleteRule, dispatch],
  );

  const activeCount = rulesState.rules.filter((r) => r.isActive).length;
  const totalCount = rulesState.rules.length;

  return (
    <>
      <div className="min-h-screen bg-[#0c0c0c] flex flex-col text-[#f5f5f5]">
        <div className="flex-1 flex justify-center p-8">
          <div className="w-full max-w-7xl">
            {/* PAGE HEADER */}
            <div className="flex items-center gap-4 mb-10">
              <div className="flex-shrink-0 w-full items-center justify-center text-center px-2">
                <div className="text-[9px] text-[#4a4a4a] tracking-[0.45em] uppercase mb-0.5">
                  RaptorGate
                </div>
                <div className="text-[13px] tracking-[0.35em] uppercase">
                  Policy Engine
                </div>
                <div className="text-[9px] text-[#06b6d4] tracking-[0.25em] mt-0.5">
                  Rule Processing Pipeline
                </div>
              </div>
            </div>
            {/* STATUS BAR */}
            <div className="bg-[#161616] border border-[#262626] px-5 py-3 mb-4 flex flex-wrap items-center gap-5 text-[11px]">
              <div className="flex items-center gap-2">
                <span className="text-[#8a8a8a] uppercase tracking-[0.2em]">
                  Module
                </span>
                <span className="relative flex items-center gap-1.5 text-[#10b981]">
                  <span className="relative flex h-1.5 w-1.5">
                    <span
                      className="absolute inline-flex h-full w-full rounded-full bg-[#10b981]"
                      style={{ animation: "pingSlow 2s ease-in-out infinite" }}
                    />
                    <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-[#10b981]" />
                  </span>
                  ACTIVE
                </span>
              </div>
              <span className="text-[#262626]">│</span>
              <div className="flex items-center gap-2">
                <span className="text-[#8a8a8a]">Total</span>
                <span className="text-[#f5f5f5] font-mono tabular-nums">
                  {totalCount}
                </span>
              </div>
              <span className="text-[#262626]">│</span>
              <div className="flex items-center gap-2">
                <span className="text-[#8a8a8a]">Active</span>
                <span className="text-[#10b981] font-mono tabular-nums">
                  {activeCount}
                </span>
              </div>
              <span className="text-[#262626]">│</span>
              <div className="flex items-center gap-2">
                <span className="text-[#8a8a8a]">Inactive</span>
                <span className="text-[#4a4a4a] font-mono tabular-nums">
                  {totalCount - activeCount}
                </span>
              </div>
            </div>
            {/* RULE LIST HEADER */}
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-3">
                <span className="text-[11px] tracking-[0.25em] uppercase">
                  Rule List
                </span>
                {!isLoading && (
                  <span className="text-[10px] text-[#4a4a4a] font-mono">
                    [{totalCount} {totalCount === 1 ? "entry" : "entries"}]
                  </span>
                )}
              </div>
              <button
                type="button"
                onClick={handleOpenCreate}
                className="btn-primary text-[10px] px-4 py-2 tracking-[0.25em] uppercase"
              >
                + New Rule
              </button>
            </div>
            {/* TABLE */}
            <div className="bg-[#161616] border border-[#262626]">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-[#262626]">
                    {[
                      "Priority",
                      "Name",
                      "Zone Pair",
                      "Content",
                      "Author",
                      "Status",
                      "Actions",
                    ].map((h, i) => (
                      <th
                        key={i}
                        className={`text-left p-4 text-xs text-[#8a8a8a] uppercase tracking-[0.2em] font-medium
                          ${i === 3 ? "hidden lg:table-cell" : ""}
                          ${i === 4 ? "hidden md:table-cell" : ""}
                          ${i === 6 ? "w-28 text-right" : ""}
                        `}
                      >
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {/* ... loading/error/empty states ... */}

                  {rulesState.rules.map((rule) => (
                    <tr
                      key={rule.id}
                      className="border-b border-[#262626] hover:bg-[#1b1b1b] transition-colors"
                    >
                      <td className="p-4">
                        <PriorityBar priority={rule.priority} />
                      </td>
                      <td className="p-4">
                        <div className="text-[#f5f5f5] text-sm font-mono">
                          {rule.name}
                        </div>
                        {rule.description ? (
                          <div className="text-[#8a8a8a] text-xs mt-0.5 max-w-[220px] truncate">
                            {rule.description}
                          </div>
                        ) : null}
                      </td>
                      <td className="p-4">
                        <span
                          className="text-xs px-2 py-0.5 border font-mono text-[#8a8a8a] tracking-wider"
                          style={{
                            borderColor: "#06b6d430",
                            backgroundColor: "#06b6d408",
                          }}
                          title={rule.zonePairId}
                        >
                          {rule.zonePairId.length > 8
                            ? rule.zonePairId.slice(0, 8) + "…"
                            : rule.zonePairId}
                        </span>
                      </td>
                      <td className="p-4 hidden lg:table-cell">
                        <span
                          className="text-[#8a8a8a] font-mono text-xs"
                          title={rule.content}
                        >
                          {rule.content.length > 44
                            ? rule.content.slice(0, 44) + "…"
                            : rule.content}
                        </span>
                      </td>
                      <td className="p-4 hidden md:table-cell">
                        <span
                          className="text-[#8a8a8a] font-mono text-xs tracking-wider"
                          title={rule.createdBy}
                        >
                          {rule.createdBy.length > 8
                            ? rule.createdBy.slice(0, 8) + "…"
                            : rule.createdBy}
                        </span>
                      </td>
                      <td className="p-4">
                        <span
                          className={`flex items-center gap-2 ${rule.isActive ? "text-[#10b981]" : "text-[#8a8a8a]"}`}
                        >
                          <span className="relative flex h-2 w-2 flex-shrink-0">
                            {rule.isActive && (
                              <span
                                className="absolute inline-flex h-full w-full rounded-full bg-[#10b981]"
                                style={{
                                  animation:
                                    "pingSlow 2.4s ease-in-out infinite",
                                }}
                              />
                            )}
                            <span
                              className={`relative inline-flex h-2 w-2 rounded-full ${rule.isActive ? "bg-[#10b981]" : "bg-[#8a8a8a]"}`}
                            />
                          </span>
                          <span className="text-xs uppercase tracking-[0.1em] font-medium">
                            {rule.isActive ? "Active" : "Inactive"}
                          </span>
                        </span>
                      </td>
                      <td className="p-4 text-right">
                        {confirmDeleteId === rule.id ? (
                          <div className="flex items-center justify-end gap-2">
                            <button
                              type="button"
                              onClick={() => handleDeleteConfirm(rule.id)}
                              disabled={isDeleting}
                              className="text-xs text-[#f43f5e] hover:text-[#ff6b6b] tracking-wider uppercase font-bold disabled:opacity-40"
                            >
                              {isDeleting ? "…" : "Confirm"}
                            </button>
                            <span className="text-[#4a4a4a] text-xs">│</span>
                            <button
                              type="button"
                              onClick={handleDeleteCancel}
                              className="text-xs text-[#8a8a8a] hover:text-[#f5f5f5] tracking-wider uppercase font-bold"
                            >
                              Cancel
                            </button>
                          </div>
                        ) : (
                          <div className="flex items-center justify-end gap-4">
                            <button
                              type="button"
                              onClick={() => handleOpenEdit(rule)}
                              className="text-[#8a8a8a] hover:text-[#06b6d4] transition-colors text-lg"
                              title="Edit"
                            >
                              ✎
                            </button>
                            <button
                              type="button"
                              onClick={() => handleDeleteClick(rule.id)}
                              className="text-[#8a8a8a] hover:text-[#f43f5e] transition-colors text-lg"
                              title="Delete"
                            >
                              ✕
                            </button>
                          </div>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {/* FOOTER */}
            <div className="mt-10 text-center text-[10px] text-[#3a3a3a] tracking-[0.3em] uppercase">
              Policy Engine
              <span className="text-[#262626] mx-3">│</span>
              Rule Processing Pipeline
              <span className="text-[#262626] mx-3">│</span>
              RaptorGate
            </div>
          </div>
        </div>
      </div>

      <RuleForm
        rule={editingRule}
        isOpen={isFormOpen}
        onClose={handleCloseForm}
        onSuccess={handleFormSuccess}
      />
    </>
  );
}
