import { useEffect } from "react";
import { useAppDispatch, useAppSelector } from "../../app/hooks";
import { useExportConfigQuery } from "../../services/config";
import ConfigControlDetailsPanel from "./ConfigControlDetailsPanel";
import ConfigControlFooter from "./ConfigControlFooter";
import ConfigControlHistoryPanel from "./ConfigControlHistoryPanel";
import ConfigControlOperationsPanel from "./ConfigControlOperationsPanel";
import ConfigControlPageHeader from "./ConfigControlPageHeader";
import ConfigControlStatusBar from "./ConfigControlStatusBar";
import { CONFIG_CONTROL_SNAPSHOTS, formatSnapshotDate } from "./mockData";
import type { ApiSuccess } from "../../types/ApiResponse";
import { setConfig } from "../../features/configSlice";
import type { ConfigSnapshot } from "./types";

const selectedSnapshot = CONFIG_CONTROL_SNAPSHOTS[0];

export default function ConfigControlLayout() {
  const dispatch = useAppDispatch();
  const configState = useAppSelector((state) => state.config);

  const { data: activeConfigSnapshot, isSuccess } = useExportConfigQuery();

  const handleExport = function (
    data: ConfigSnapshot,
    fileName: string = "export.json",
  ) {
    const jsonString = JSON.stringify(data, null, 2);

    const blob = new Blob([jsonString], { type: "application/json" });

    const url = URL.createObjectURL(blob);

    const link = document.createElement("a");
    link.href = url;
    link.download = fileName; // nazwa pliku, pod jaką zostanie zapisany

    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    URL.revokeObjectURL(url);
  };

  useEffect(() => {
    if (!activeConfigSnapshot) return;

    const payload = activeConfigSnapshot as ApiSuccess<ConfigSnapshot>;
    console.log("payload: ", payload.data);

    dispatch(setConfig({ config: payload.data }));
  }, [activeConfigSnapshot, dispatch, isSuccess]);

  return (
    <div className="min-h-screen bg-[#0c0c0c] flex flex-col text-[#f5f5f5]">
      <div className="flex-1 flex justify-center p-8">
        <div className="w-full max-w-[100rem]">
          <ConfigControlPageHeader />

          <ConfigControlStatusBar
            activeVersion={configState.config.versionNumber}
            snapshotCount={CONFIG_CONTROL_SNAPSHOTS.length}
            lastUpdate={formatSnapshotDate(configState.config.createdAt)}
          />

          <div className="grid grid-cols-1 xl:grid-cols-[minmax(360px,0.9fr)_minmax(0,1.55fr)] gap-4">
            <ConfigControlOperationsPanel
              onExport={handleExport}
              data={configState.config}
              fileName="selected-snapshot.json"
            />
            <ConfigControlHistoryPanel
              snapshots={CONFIG_CONTROL_SNAPSHOTS}
              selectedSnapshotId={selectedSnapshot.id}
            />
          </div>

          <ConfigControlDetailsPanel snapshot={configState.config} />
          <ConfigControlFooter />
        </div>
      </div>
    </div>
  );
}
