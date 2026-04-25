import { useRef, useState, type ChangeEvent } from "react";
import type { ConfigSnapshot } from "./types";
import { useImportConfigMutation, useApplyConfigMutation } from "../../services/config";
import type { ApiFailure, ApiSuccess } from "../../types/ApiResponse";
import type { SnapshotType } from "../../types/config/Config";
import { generateSHA256 } from "../../utils/generateSHA256";

const APPLY_PREVIEW = `{
  "snapshotType": "manual_import",
  "isActive": true,
  "changeSummary": "Applied current running config"
}`;

const IMPORT_PREVIEW = `{
  "id": "123e4567-e89b-12d3-a456-426614174000",
  "versionNumber": 19,
  "snapshotType": "manual_import",
  "checksum": "0374c1...600f12fc",
  "isActive": true,
  "payloadJson": { "bundle": {} },
  "changeSummary": "Imported configuration from admin panel",
  "createdAt": "2024-06-01T12:00:00Z",
  "createdBy": "345e4567-e89b-12d3-a456-426614174000"
}`;

type OperationTab = "apply" | "import" | "export" | "rollback";

const OPERATION_TABS: { key: OperationTab; label: string }[] = [
  { key: "apply", label: "Apply" },
  { key: "import", label: "Import" },
  { key: "export", label: "Export" },
  { key: "rollback", label: "Rollback" },
];

type ConfigControlOperationsPanelProps = {
  data: ConfigSnapshot;
  fileName: string;
  onExport: (data: ConfigSnapshot, fileName: string) => void;
};

export default function ConfigControlOperationsPanel(
  props: ConfigControlOperationsPanelProps,
) {
  const [activeTab, setActiveTab] = useState<OperationTab>("apply");
  const [importedConfig, setImportedConfig] = useState<string>(IMPORT_PREVIEW);
  const [responseError, setResponseError] = useState<ApiFailure>();

  const [applySnapshotType, setApplySnapshotType] = useState<SnapshotType>("manual_import");
  const [applyIsActive, setApplyIsActive] = useState(true);
  const [applyChangeSummary, setApplyChangeSummary] = useState("Applied current running config");

  const [importConfig, { isError: isImportError, isSuccess: isImportSuccess }] =
    useImportConfigMutation();

  const [applyConfig, { isError: isApplyError, isSuccess: isApplySuccess, isLoading: isApplyLoading, error: applyError }] =
    useApplyConfigMutation();

  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleApply = async function () {
    try {
      await applyConfig({
        snapshotType: applySnapshotType,
        isActive: applyIsActive,
        changeSummary: applyChangeSummary || null,
      }).unwrap();
    } catch (error) {
      setResponseError(error as ApiFailure);
    }
  };

  const handleButtonClick = async function () {
    fileInputRef.current?.click();
  };

  const handleImport = async function () {
    try {
      const config = JSON.parse(importedConfig) as ConfigSnapshot;
      const bundleChecksum = await generateSHA256(
        JSON.stringify(config.payloadJson),
      );

      const response = await importConfig({
        ...config,
        checksum: bundleChecksum,
      }).unwrap();

      if (response.statusCode === 201) {
        const payload = response as ApiSuccess<ConfigSnapshot>;

        return payload.data;
      }
    } catch (error) {
      setResponseError(error as ApiFailure);
    }
  };

  const handleImportFile = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];

    if (!file) {
      return;
    }

    try {
      const fileContent = await file.text();

      const parsedData = JSON.parse(fileContent) as ConfigSnapshot;

      console.log("Pomyślnie wczytano i sparsowano dane:", parsedData);
      setImportedConfig(JSON.stringify(parsedData, null, 2));
    } catch (error) {
      console.error("Błąd podczas odczytu pliku JSON:", error);
      setImportedConfig("Wybrany plik nie jest poprawnym plikiem JSON.");
    } finally {
      event.target.value = "";
    }
  };

  return (
    <aside className="bg-[#161616] border border-[#262626]">
      <div className="flex items-center justify-between px-5 py-4 border-b border-[#262626]">
        <span className="text-[12px] tracking-[0.22em] uppercase">
          Operations
        </span>
        <span className="text-[10px] text-[#4a4a4a] tracking-[0.12em]">
          /config/*
        </span>
      </div>

      <div
        className="flex overflow-x-auto border-b border-[#262626]"
        role="tablist"
      >
        {OPERATION_TABS.map((tab) => (
          <button
            key={tab.key}
            type="button"
            role="tab"
            aria-selected={activeTab === tab.key}
            onClick={() => setActiveTab(tab.key)}
            className={`px-4 py-3 text-base whitespace-nowrap transition ${
              activeTab === tab.key
                ? "text-[#06b6d4] border-b-2 border-[#06b6d4]"
                : "text-[#8a8a8a] hover:text-white"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      <div className="p-5">
        {activeTab === "apply" && (
          <section className="bg-[#131313] border border-[#262626] p-4 space-y-3">
            <div className="text-[11px] tracking-[0.2em] uppercase text-[#06b6d4]">
              POST /config/apply
            </div>
            <div className="space-y-3">
              <div className="space-y-1.5">
                <label className="text-[10px] tracking-[0.16em] uppercase text-[#4a4a4a]">
                  snapshotType
                </label>
                <select
                  value={applySnapshotType}
                  onChange={(e) => setApplySnapshotType(e.target.value as SnapshotType)}
                  className="w-full bg-[#0c0c0c] border border-[#262626] px-3 py-2 text-base text-[#f5f5f5]"
                >
                  <option value="manual_import">manual_import</option>
                  <option value="rollback_point">rollback_point</option>
                  <option value="auto_save">auto_save</option>
                </select>
              </div>

              <button
                type="button"
                onClick={() => setApplyIsActive((v) => !v)}
                className="w-full flex items-center justify-between gap-3 bg-[#0f0f0f] border border-[#262626] px-3 py-2.5 text-left"
              >
                <div>
                  <p className="text-[11px] tracking-[0.14em] uppercase text-[#8a8a8a]">
                    isActive
                  </p>
                  <p className="text-[10px] text-[#4a4a4a]">
                    Publish as active snapshot
                  </p>
                </div>
                <div className={`relative w-9 h-5 rounded-full transition-colors ${applyIsActive ? "bg-[#06b6d4]" : "bg-[#262626]"}`}>
                  <span className={`absolute top-[3px] h-3.5 w-3.5 rounded-full bg-white transition-all ${applyIsActive ? "right-[3px]" : "left-[3px]"}`} />
                </div>
              </button>

              <div className="space-y-1.5">
                <label className="text-[10px] tracking-[0.16em] uppercase text-[#4a4a4a]">
                  changeSummary
                </label>
                <textarea
                  rows={2}
                  value={applyChangeSummary}
                  onChange={(e) => setApplyChangeSummary(e.target.value)}
                  className="w-full bg-[#0c0c0c] border border-[#262626] px-3 py-2 text-base text-[#f5f5f5]"
                />
              </div>
            </div>

            <pre className="text-[11px] text-[#b2c0c5] bg-[#0e0e0e] border border-[#262626] p-3 overflow-auto whitespace-pre-wrap leading-5">
              {JSON.stringify({ snapshotType: applySnapshotType, isActive: applyIsActive, changeSummary: applyChangeSummary || null }, null, 2)}
            </pre>

            {isApplyError && (
              <p className="text-[#ef4444] text-xs">
                {(applyError as ApiFailure)?.message ?? "Apply failed"}
              </p>
            )}

            {isApplySuccess && (
              <p className="text-[#10b981] text-xs">
                Snapshot applied successfully.
              </p>
            )}

            <button
              type="button"
              disabled={isApplyLoading}
              onClick={handleApply}
              className="w-full border border-[#06b6d4] text-[#06b6d4] text-[11px] tracking-[0.16em] uppercase py-2.5 hover:bg-[#06b6d4] hover:text-black transition disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {isApplyLoading ? "Applying…" : "Apply Snapshot"}
            </button>
          </section>
        )}

        {activeTab === "import" && (
          <section className="bg-[#131313] border border-[#262626] p-4 space-y-3">
            <div className="text-[11px] tracking-[0.2em] uppercase text-[#8a8a8a]">
              POST /config/import
            </div>
            <textarea
              rows={10}
              className="w-full bg-[#0c0c0c] border border-[#262626] px-3 py-2 text-xs text-[#f5f5f5] leading-5"
              value={importedConfig}
              onChange={(e) => setImportedConfig(e.target.value)}
            />
            <div className="flex gap-2">
              <input
                type="file"
                ref={fileInputRef}
                accept=".json"
                className="hidden"
                onChange={handleImportFile}
              />
              <button
                type="button"
                className="flex-1 border border-[#262626] text-[#8a8a8a] text-[11px] tracking-[0.14em] uppercase py-2 hover:text-[#f5f5f5] hover:border-[#8a8a8a] transition"
                onClick={handleButtonClick}
              >
                Load Selected
              </button>
              <button
                type="button"
                className="flex-1 border border-[#06b6d4] text-[#06b6d4] text-[11px] tracking-[0.14em] uppercase py-2 hover:bg-[#06b6d4] hover:text-black transition"
                onClick={handleImport}
              >
                Import
              </button>
            </div>

            {isImportError && (
              <p className="text-[#ef4444] text-xs mt-[0.1rem] mb-[0.55rem]">
                {responseError?.message}
              </p>
            )}

            {isImportSuccess && (
              <p className="text-[#10b981] text-xs mt-[0.1rem] mb-[0.55rem]">
                Active configuration imported successfully. New snapshot created
                and
              </p>
            )}
          </section>
        )}

        {activeTab === "export" && (
          <section className="bg-[#131313] border border-[#262626] p-4 space-y-3">
            <div className="text-[11px] tracking-[0.2em] uppercase text-[#8a8a8a]">
              GET /config/export
            </div>
            <p className="text-[12px] text-[#8a8a8a] leading-5">
              Export active snapshot as full JSON payload for backup or
              migration.
            </p>
            <button
              type="button"
              className="cursor-pointer w-full border border-[#06b6d4] text-[#06b6d4] text-[11px] tracking-[0.14em] uppercase py-2 hover:bg-[#06b6d4] hover:text-black transition"
              onClick={() => {
                props.onExport(props.data, props.fileName);
              }}
            >
              Export Active Snapshot
            </button>
          </section>
        )}

        {activeTab === "rollback" && (
          <section className="bg-[#131313] border border-[#262626] p-4 space-y-3">
            <div className="text-[11px] tracking-[0.2em] uppercase text-[#8a8a8a]">
              POST /config/rollback/{"{id}"}
            </div>
            <div className="space-y-1.5">
              <label className="text-[10px] tracking-[0.16em] uppercase text-[#4a4a4a]">
                Target snapshot ID
              </label>
              <input
                className="w-full bg-[#0c0c0c] border border-[#262626] px-3 py-2 text-base text-[#f5f5f5]"
                value="5f4e635f-d6d5-4ce4-a8ff-bf8d7184db11"
                readOnly
              />
            </div>
            <button
              type="button"
              className="w-full border border-[#06b6d4] text-[#06b6d4] text-[11px] tracking-[0.14em] uppercase py-2 hover:bg-[#06b6d4] hover:text-black transition"
            >
              Rollback To Snapshot
            </button>
          </section>
        )}
      </div>
    </aside>
  );
}
