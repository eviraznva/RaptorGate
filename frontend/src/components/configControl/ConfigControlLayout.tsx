import { useEffect, useMemo } from "react";
import { useAppDispatch, useAppSelector } from "../../app/hooks";
import {
  useExportConfigQuery,
  useGetConfigHistoryQuery,
  type GetConfigHistoryPayload,
} from "../../services/config";
import ConfigControlDetailsPanel from "./ConfigControlDetailsPanel";
import ConfigControlFooter from "./ConfigControlFooter";
import ConfigControlHistoryPanel from "./ConfigControlHistoryPanel";
import ConfigControlOperationsPanel from "./ConfigControlOperationsPanel";
import ConfigControlPageHeader from "./ConfigControlPageHeader";
import ConfigControlStatusBar from "./ConfigControlStatusBar";
import { formatSnapshotDate } from "./mockData";
import type { ApiFailure, ApiSuccess } from "../../types/ApiResponse";
import {
  setConfig,
  setConfigHistory,
  setSelectedSnapshotId,
} from "../../features/configSlice";
import type { ConfigSnapshot } from "./types";

export default function ConfigControlLayout() {
  const dispatch = useAppDispatch();
  const configState = useAppSelector((state) => state.config);

  const { data: activeConfigSnapshot, isSuccess } = useExportConfigQuery();
  const {
    data: historyData,
    isLoading: isHistoryLoading,
    isError: isHistoryError,
    error: historyError,
  } = useGetConfigHistoryQuery();

  const snapshots = useMemo(() => {
    if (!historyData) return [];
    return (historyData as ApiSuccess<GetConfigHistoryPayload>).data.configHistory ?? [];
  }, [historyData]);

  const selectedSnapshot = useMemo(() => {
    return (
      configState.configHistory.find(
        (snapshot) => snapshot.id === configState.selectedSnapshotId,
      ) ?? null
    );
  }, [configState.configHistory, configState.selectedSnapshotId]);

  const selectedSnapshotForDisplay =
    selectedSnapshot?.id === configState.config.id
      ? configState.config
      : selectedSnapshot;

  const historyErrorMessage = isHistoryError
    ? ((historyError as ApiFailure)?.message ?? "Failed to load snapshot history")
    : null;

  const handleExport = function (
    data: ConfigSnapshot,
    fileName: string = "export.json",
  ) {
    const jsonString = JSON.stringify(data, null, 2);

    const blob = new Blob([jsonString], { type: "application/json" });

    const url = URL.createObjectURL(blob);

    const link = document.createElement("a");
    link.href = url;
    link.download = fileName;

    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    URL.revokeObjectURL(url);
  };

  useEffect(() => {
    if (!activeConfigSnapshot) return;

    const payload = activeConfigSnapshot as ApiSuccess<ConfigSnapshot>;

    dispatch(setConfig({ config: payload.data }));
  }, [activeConfigSnapshot, dispatch, isSuccess]);

  useEffect(() => {
    dispatch(setConfigHistory({ configHistory: snapshots }));
  }, [snapshots, dispatch]);

  return (
    <div className="min-h-screen bg-[#0c0c0c] flex flex-col text-[#f5f5f5]">
      <div className="flex-1 flex justify-center p-8">
        <div className="w-full max-w-[100rem]">
          <ConfigControlPageHeader />

          <ConfigControlStatusBar
            activeVersion={configState.config.versionNumber}
            snapshotCount={configState.configHistory.length}
            lastUpdate={formatSnapshotDate(configState.config.createdAt)}
          />

          <div className="grid grid-cols-1 xl:grid-cols-[minmax(360px,0.9fr)_minmax(0,1.55fr)] gap-4">
            <ConfigControlOperationsPanel
              onExport={handleExport}
              onRollbackSuccess={(snapshot) => {
                dispatch(setConfig({ config: snapshot }));
                dispatch(setSelectedSnapshotId(snapshot.id));
              }}
              data={configState.config}
              selectedSnapshot={selectedSnapshotForDisplay}
              fileName="selected-snapshot.json"
            />
            <ConfigControlHistoryPanel
              snapshots={configState.configHistory}
              selectedSnapshotId={configState.selectedSnapshotId}
              activeSnapshotId={
                configState.config.isActive ? configState.config.id : ""
              }
              isLoading={isHistoryLoading}
              errorMessage={historyErrorMessage}
              onSelectSnapshot={(id) => dispatch(setSelectedSnapshotId(id))}
            />
          </div>

          <ConfigControlDetailsPanel
            snapshot={selectedSnapshotForDisplay ?? configState.config}
          />
          <ConfigControlFooter />
        </div>
      </div>
    </div>
  );
}
