import { useCallback, useEffect, useState } from "react";
import NatRulesPageHeader from "../components/nat/NatRulesPageHeader";
import NatRulesStatusBar from "../components/nat/NatRulesStatusBar";
import NatRulesTable, { type NatFilter } from "../components/nat/NatRulesTable";
import NatRuleForm from "../components/nat/NatRuleForm";
import NatRulesFooter from "../components/nat/NatRulesFooter";
import type { NatRule } from "../types/nat/NatRule";
import { useAppDispatch, useAppSelector } from "../app/hooks";
import {
  useCreateNatRuleMutation,
  useDeleteNatRuleMutation,
  useGetNatRulesQuery,
  useUpdateNatRuleMutation,
  type CreateNatRuleBody,
  type NatRulesPayload,
} from "../services/natRules";
import * as natRulesSliceReducers from "../features/natRulesSlice";
import type { ApiSuccess } from "../types/ApiResponse";

export default function NatRules() {
  const dispatch = useAppDispatch();
  const natRulesState = useAppSelector((state) => state.natRules);

  const { data } = useGetNatRulesQuery();
  const [createNatRule] = useCreateNatRuleMutation();
  const [updateNatRule] = useUpdateNatRuleMutation();
  const [deleteNatRule] = useDeleteNatRuleMutation();

  const [activeFilter, setActiveFilter] = useState<NatFilter>("all");
  const [isFormOpen, setIsFormOpen] = useState(false);
  const [editingRule, setEditingRule] = useState<NatRule | null>(null);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);

  useEffect(() => {
    if (!data) return;
    const payload = data as ApiSuccess<NatRulesPayload>;
    dispatch(natRulesSliceReducers.setNatRules(payload.data.natRules));
  }, [data, dispatch]);

  const handleNew = useCallback(() => {
    setEditingRule(null);
    setIsFormOpen(true);
  }, []);

  const handleEdit = useCallback((rule: NatRule) => {
    setEditingRule(rule);
    setIsFormOpen(true);
  }, []);

  const handleCloseForm = useCallback(() => setIsFormOpen(false), []);

  const handleSuccess = useCallback(
    async (body: CreateNatRuleBody, mode: "create" | "edit", id?: string) => {
      if (mode === "edit") {
        if (!id) return;
        const res = await updateNatRule({ id, body }).unwrap();
        if (res.statusCode !== 200) return;
        const { data } = res as ApiSuccess<{ natRule: NatRule }>;
        dispatch(natRulesSliceReducers.editNatRule(data.natRule));
      }

      if (mode === "create") {
        const res = await createNatRule(body).unwrap();
        if (res.statusCode !== 201) return;
        const { data } = res as ApiSuccess<{ natRule: NatRule }>;
        dispatch(natRulesSliceReducers.addNatRule(data.natRule));
      }

      setIsFormOpen(false);
    },
    [createNatRule, dispatch, updateNatRule],
  );

  const handleDeleteClick = useCallback((id: string) => setConfirmDeleteId(id), []);
  const handleDeleteCancel = useCallback(() => setConfirmDeleteId(null), []);

  const handleDeleteConfirm = useCallback(
    async (id: string) => {
      await deleteNatRule(id).unwrap();
      dispatch(natRulesSliceReducers.deleteNatRule(id));
      setConfirmDeleteId(null);
    },
    [deleteNatRule, dispatch],
  );

  return (
    <>
      <div className="min-h-screen bg-[#0c0c0c] flex flex-col text-[#f5f5f5]">
        <div className="flex-1 flex justify-center p-8">
          <div className="w-full max-w-7xl">
            <NatRulesPageHeader />
            <NatRulesStatusBar rules={natRulesState.natRules} />
            <div className="bg-[#161616] border border-[#262626] mb-6 p-6">
              <NatRulesTable
                rules={natRulesState.natRules}
                activeFilter={activeFilter}
                onFilterChange={setActiveFilter}
                confirmDeleteId={confirmDeleteId}
                onNew={handleNew}
                onEdit={handleEdit}
                onDeleteClick={handleDeleteClick}
                onDeleteConfirm={handleDeleteConfirm}
                onDeleteCancel={handleDeleteCancel}
              />
            </div>
            <NatRulesFooter />
          </div>
        </div>
      </div>

      <NatRuleForm
        rule={editingRule}
        isOpen={isFormOpen}
        onClose={handleCloseForm}
        onSuccess={handleSuccess}
      />
    </>
  );
}
