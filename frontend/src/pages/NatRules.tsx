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
  const [deleteNatRule, { isError: isDeletingError }] =
    useDeleteNatRuleMutation();

  useEffect(() => {
    if (!data) return;
    const payload = data as ApiSuccess<NatRulesPayload>;
    dispatch(natRulesSliceReducers.setNatRules(payload.data.natRules));
  }, [data, dispatch]);

  const [activeFilter, setActiveFilter] = useState<NatFilter>("all");

  const [isFormOpen, setIsFormOpen] = useState(false);
  const [editingRule, setEditingRule] = useState<NatRule | null>(null);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);

  const handleCreateNatRule = async function (data: CreateNatRuleBody) {
    try {
      const res = await createNatRule(data).unwrap();
      if (res.statusCode === 201) {
        const { data } = res as ApiSuccess<{ natRule: NatRule }>;
        return data.natRule;
      }
    } catch (error) {}
  };

  const handleUpdateNatRule = async function (
    id: string,
    data: Partial<CreateNatRuleBody>,
  ) {
    try {
      const res = await updateNatRule({ id, ...data }).unwrap();
      if (res.statusCode === 200) {
        const { data } = res as ApiSuccess<{ natRule: NatRule }>;
        return data.natRule;
      }
    } catch (error) {}
  };

  const handleDeleteNatRuleApi = async function (id: string) {
    try {
      return await deleteNatRule(id).unwrap();
    } catch (error) {}
  };

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
    async (rule: NatRule, mode: "create" | "edit") => {
      const payload: CreateNatRuleBody = {
        type: rule.type,
        isActive: rule.isActive,
        priority: rule.priority,
        sourceIp: rule.sourceIp || null,
        destinationIp: rule.destinationIp || null,
        sourcePort: rule.sourcePort || null,
        destinationPort: rule.destinationPort || null,
        translatedIp: rule.translatedIp || null,
        translatedPort: rule.translatedPort || null,
      };

      if (mode === "edit") {
        const updatedRule = await handleUpdateNatRule(rule.id, payload);

        if (updatedRule === undefined) return;
        dispatch(natRulesSliceReducers.editNatRule(updatedRule));
      }

      if (mode === "create") {
        const newRule = await handleCreateNatRule(payload);

        if (newRule === undefined) return;
        dispatch(natRulesSliceReducers.addNatRule(newRule));
      }

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
      await handleDeleteNatRuleApi(id);
      if (!isDeletingError) dispatch(natRulesSliceReducers.deleteNatRule(id));
      setConfirmDeleteId(null);
    },
    [dispatch, isDeletingError],
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
