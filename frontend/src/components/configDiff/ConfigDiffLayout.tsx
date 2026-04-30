import { useEffect, useMemo } from "react";
import { useAppDispatch, useAppSelector } from "../../app/hooks";
import { useGetConfigHistoryQuery, useGetConfigDiffQuery } from "../../services/config";
import {
  setBaseId,
  setTargetId,
  setTypeFilter,
  setSectionFilter,
  setSearch,
  setSelectedChangeIndex,
} from "../../features/configDiffSlice";
import type { ApiSuccess } from "../../types/ApiResponse";
import type { GetConfigHistoryPayload } from "../../services/config";
import type { ConfigDiffResult, ConfigDiffChange } from "../../types/config/ConfigDiff";
import ConfigDiffPageHeader from "./ConfigDiffPageHeader";
import ConfigDiffStatusBar from "./ConfigDiffStatusBar";
import ConfigDiffComparePanel from "./ConfigDiffComparePanel";
import ConfigDiffSnapshotPair from "./ConfigDiffSnapshotPair";
import ConfigDiffSummaryPanel from "./ConfigDiffSummaryPanel";
import ConfigDiffChangesPanel from "./ConfigDiffChangesPanel";
import ConfigDiffDetailPanel from "./ConfigDiffDetailPanel";
import ConfigDiffFooter from "./ConfigDiffFooter";

export default function ConfigDiffLayout() {
  const dispatch = useAppDispatch();
  const { baseId, targetId, typeFilter, sectionFilter, search, selectedChangeIndex } =
    useAppSelector((state) => state.configDiff);

  const { data: historyData } = useGetConfigHistoryQuery();
  const { data: diffData } = useGetConfigDiffQuery(
    { baseId, targetId },
    { skip: !baseId || !targetId },
  );

  const snapshots = useMemo(() => {
    if (!historyData) return [];
    return (historyData as ApiSuccess<GetConfigHistoryPayload>).data.configHistory ?? [];
  }, [historyData]);

  const diffResult = useMemo<ConfigDiffResult | null>(() => {
    if (!diffData) return null;
    return (diffData as ApiSuccess<ConfigDiffResult>).data;
  }, [diffData]);

  useEffect(() => {
    if (snapshots.length >= 2 && !baseId) {
      dispatch(setBaseId(snapshots[1].id));
      dispatch(setTargetId(snapshots[0].id));
    }
  }, [snapshots, baseId, dispatch]);

  const allChanges = diffResult?.changes ?? [];

  const filteredChanges = useMemo<ConfigDiffChange[]>(() => {
    const searchTerm = search.trim().toLowerCase();
    return allChanges.filter((change) => {
      if (typeFilter !== 'all' && change.type !== typeFilter) return false;
      if (sectionFilter !== 'all' && change.section !== sectionFilter) return false;
      if (!searchTerm) return true;
      return [change.type, change.section, change.path, change.entityId ?? '']
        .join(' ')
        .toLowerCase()
        .includes(searchTerm);
    });
  }, [allChanges, typeFilter, sectionFilter, search]);

  const safeSelectedIndex = selectedChangeIndex >= filteredChanges.length
    ? 0
    : selectedChangeIndex;

  const selectedChange = filteredChanges[safeSelectedIndex] ?? null;

  const baseSnapshot = diffResult?.baseSnapshot ?? null;
  const targetSnapshot = diffResult?.targetSnapshot ?? null;

  return (
    <div className="min-h-screen bg-[#0c0c0c] flex flex-col text-[#f5f5f5]">
      <div className="flex-1 flex justify-center px-6 pt-[30px] pb-12">
        <div className="w-full max-w-[1480px] grid gap-[18px]">
          <ConfigDiffPageHeader />

          <ConfigDiffStatusBar
            baseVersion={baseSnapshot?.versionNumber ?? null}
            targetVersion={targetSnapshot?.versionNumber ?? null}
          />

          <ConfigDiffComparePanel
            snapshots={snapshots}
            baseId={baseId}
            targetId={targetId}
            onBaseChange={(id) => dispatch(setBaseId(id))}
            onTargetChange={(id) => dispatch(setTargetId(id))}
          />

          <ConfigDiffSnapshotPair base={baseSnapshot} target={targetSnapshot} />

          <div className="grid grid-cols-1 xl:grid-cols-[minmax(320px,0.68fr)_minmax(0,1.7fr)] gap-[18px]">
            <ConfigDiffSummaryPanel
              summary={diffResult?.summary ?? null}
              totalChanges={allChanges.length}
              typeFilter={typeFilter as 'all' | 'added' | 'removed' | 'modified'}
              sectionFilter={sectionFilter}
              onTypeFilter={(type) => dispatch(setTypeFilter(type))}
              onSectionFilter={(section) => dispatch(setSectionFilter(section))}
            />

            <ConfigDiffChangesPanel
              changes={filteredChanges}
              typeFilter={typeFilter as 'all' | 'added' | 'removed' | 'modified'}
              search={search}
              selectedIndex={safeSelectedIndex}
              onTypeFilter={(type) => dispatch(setTypeFilter(type))}
              onSearch={(value) => dispatch(setSearch(value))}
              onSelectChange={(index) => dispatch(setSelectedChangeIndex(index))}
            />
          </div>

          <ConfigDiffDetailPanel change={selectedChange} />

          <ConfigDiffFooter />
        </div>
      </div>
    </div>
  );
}
