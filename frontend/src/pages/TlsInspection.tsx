import { useEffect, useMemo, useState } from "react";
import { Icon } from "@iconify/react";
import {
  useClearDecryptionExclusionsMutation,
  useGetDecryptionExclusionStatsQuery,
  useListDecryptionExclusionsQuery,
} from "../services/decryptionExclusions";
import {
  useGetDecryptionMirrorConfigQuery,
  useUpdateDecryptionMirrorConfigMutation,
} from "../services/decryptionMirror";
import {
  useCreateSslBypassDomainMutation,
  useDeleteSslBypassDomainMutation,
  useGetSslBypassDomainsQuery,
} from "../services/sslBypass";
import type { ApiFailure, ApiSuccess } from "../types/ApiResponse";
import {
  defaultDecryptionMirrorConfig,
  type DecryptionMirrorConfig,
  type DecryptionMirrorPayload,
} from "../types/ssl/DecryptionMirror";
import type { SslBypassDomainsPayload } from "../types/ssl/SslBypass";
import type {
  DecryptionExclusionListPayload,
  DecryptionExclusionStatsPayload,
} from "../types/ssl/DecryptionExclusion";
import {
  normalizeBypassDomainInput,
  validateBypassDomainInput,
} from "../components/tlsInspection/validation";

type TlsInspectionTab = "mirror" | "bypass" | "exclusions";

const tabs: { key: TlsInspectionTab; label: string }[] = [
  { key: "mirror", label: "Mirror" },
  { key: "bypass", label: "Bypass domains" },
  { key: "exclusions", label: "Local exclusions" },
];

function cloneConfig(config: DecryptionMirrorConfig): DecryptionMirrorConfig {
  return JSON.parse(JSON.stringify(config)) as DecryptionMirrorConfig;
}

function validateMirrorConfig(config: DecryptionMirrorConfig): string[] {
  const errors: string[] = [];

  if (config.enabled && config.targetHost.trim().length === 0) {
    errors.push("Target host is required when mirror is enabled.");
  }

  if (config.enabled && (config.targetPort < 1 || config.targetPort > 65535)) {
    errors.push("Target port must be in range 1..65535.");
  }

  if (config.enabled && !config.includeClientToServer && !config.includeServerToClient) {
    errors.push("At least one direction must be enabled.");
  }

  if (config.maxSessionBytes < 1) {
    errors.push("Max session bytes must be at least 1.");
  }

  return errors;
}

function requestMessage(error: unknown): string {
  return (error as ApiFailure).message ?? "Request failed.";
}

export default function TlsInspection() {
  const [activeTab, setActiveTab] = useState<TlsInspectionTab>("mirror");
  const [draft, setDraft] = useState<DecryptionMirrorConfig>(
    cloneConfig(defaultDecryptionMirrorConfig),
  );
  const [applied, setApplied] = useState<DecryptionMirrorConfig>(
    cloneConfig(defaultDecryptionMirrorConfig),
  );
  const [mirrorRequestError, setMirrorRequestError] = useState<string | null>(null);
  const [bypassRequestError, setBypassRequestError] = useState<string | null>(null);
  const [exclusionRequestError, setExclusionRequestError] = useState<string | null>(null);
  const [newBypassDomain, setNewBypassDomain] = useState("");

  const {
    data: exclusionStatsData,
    isError: isExclusionStatsError,
  } = useGetDecryptionExclusionStatsQuery();
  const {
    data: exclusionListData,
    isLoading: isExclusionListLoading,
    isError: isExclusionListError,
  } = useListDecryptionExclusionsQuery();
  const [clearDecryptionExclusions, { isLoading: isClearingExclusions }] =
    useClearDecryptionExclusionsMutation();
  const {
    data: mirrorData,
    isLoading: isMirrorLoading,
    isError: isMirrorError,
  } = useGetDecryptionMirrorConfigQuery();
  const [updateMirrorConfig, { isLoading: isSavingMirror }] =
    useUpdateDecryptionMirrorConfigMutation();
  const {
    data: bypassData,
    isLoading: isBypassLoading,
    isError: isBypassError,
  } = useGetSslBypassDomainsQuery();
  const [createBypassDomain, { isLoading: isCreatingBypass }] =
    useCreateSslBypassDomainMutation();
  const [deleteBypassDomain, { isLoading: isDeletingBypass }] =
    useDeleteSslBypassDomainMutation();

  useEffect(() => {
    if (!mirrorData) {
      return;
    }

    const payload = (mirrorData as ApiSuccess<DecryptionMirrorPayload>).data
      .decryptionMirror;

    let cancelled = false;
    queueMicrotask(() => {
      if (cancelled) {
        return;
      }

      setMirrorRequestError(null);
      setDraft(cloneConfig(payload));
      setApplied(cloneConfig(payload));
    });

    return () => {
      cancelled = true;
    };
  }, [mirrorData]);

  const bypassDomains = useMemo(() => {
    if (!bypassData) {
      return [];
    }

    return (bypassData as ApiSuccess<SslBypassDomainsPayload>).data
      .bypassDomains;
  }, [bypassData]);

  const exclusionStats = useMemo(() => {
    if (!exclusionStatsData) {
      return { activeExclusions: 0, trackedFailures: 0 };
    }

    return (exclusionStatsData as ApiSuccess<DecryptionExclusionStatsPayload>)
      .data;
  }, [exclusionStatsData]);

  const decryptionExclusions = useMemo(() => {
    if (!exclusionListData) {
      return [];
    }

    return (exclusionListData as ApiSuccess<DecryptionExclusionListPayload>)
      .data.exclusions;
  }, [exclusionListData]);

  const mirrorErrors = useMemo(() => validateMirrorConfig(draft), [draft]);
  const bypassInputErrors = useMemo(() => {
    if (newBypassDomain.trim().length === 0) {
      return [];
    }

    return validateBypassDomainInput(newBypassDomain);
  }, [newBypassDomain]);

  const uiErrors = useMemo(() => {
    const next: string[] = [];

    if (activeTab === "mirror") {
      next.push(...mirrorErrors);
    }

    if (activeTab === "bypass") {
      next.push(...bypassInputErrors);
    }

    if (isMirrorError) {
      next.unshift("TLS mirror: failed to load config from backend.");
    }

    if (isBypassError) {
      next.unshift("TLS bypass domains: failed to load list from backend.");
    }

    if (isExclusionStatsError || isExclusionListError) {
      next.unshift("TLS local exclusions: failed to load state from backend.");
    }

    if (mirrorRequestError) {
      next.unshift(`TLS mirror: ${mirrorRequestError}`);
    }

    if (bypassRequestError) {
      next.unshift(`TLS bypass domains: ${bypassRequestError}`);
    }

    if (exclusionRequestError) {
      next.unshift(`TLS local exclusions: ${exclusionRequestError}`);
    }

    return next;
  }, [
    activeTab,
    bypassInputErrors,
    bypassRequestError,
    exclusionRequestError,
    isBypassError,
    isExclusionListError,
    isExclusionStatsError,
    isMirrorError,
    mirrorErrors,
    mirrorRequestError,
  ]);

  const hasMirrorChanges = useMemo(
    () => JSON.stringify(draft) !== JSON.stringify(applied),
    [draft, applied],
  );

  const updateDraft = (partial: Partial<DecryptionMirrorConfig>) => {
    setDraft((current) => ({
      ...current,
      ...partial,
    }));
  };

  const handleApplyMirror = async () => {
    try {
      setMirrorRequestError(null);
      const response = await updateMirrorConfig({
        ...draft,
        targetHost: draft.targetHost.trim(),
      }).unwrap();
      const payload = (response as ApiSuccess<DecryptionMirrorPayload>).data
        .decryptionMirror;

      setDraft(cloneConfig(payload));
      setApplied(cloneConfig(payload));
    } catch (error) {
      setMirrorRequestError(requestMessage(error));
    }
  };

  const handleCreateBypass = async () => {
    const domain = normalizeBypassDomainInput(newBypassDomain);
    const errors = validateBypassDomainInput(domain);
    if (errors.length > 0) {
      return;
    }

    try {
      setBypassRequestError(null);
      await createBypassDomain({ domain }).unwrap();
      setNewBypassDomain("");
    } catch (error) {
      setBypassRequestError(requestMessage(error));
    }
  };

  const handleDeleteBypass = async (id: string) => {
    try {
      setBypassRequestError(null);
      await deleteBypassDomain(id).unwrap();
    } catch (error) {
      setBypassRequestError(requestMessage(error));
    }
  };

  const handleClearExclusions = async () => {
    try {
      setExclusionRequestError(null);
      await clearDecryptionExclusions().unwrap();
    } catch (error) {
      setExclusionRequestError(requestMessage(error));
    }
  };

  const canCreateBypass =
    newBypassDomain.trim().length > 0 &&
    bypassInputErrors.length === 0 &&
    !isCreatingBypass &&
    !isDeletingBypass;

  return (
    <div className="min-h-screen bg-[#0c0c0c] flex flex-col text-[#f5f5f5]">
      <div className="flex-1 flex justify-center p-8">
        <div className="w-full max-w-6xl">
          <div className="flex items-center justify-center mb-8">
            <div className="flex-1 h-px bg-gradient-to-r from-transparent via-[#06b6d4] to-transparent" />
            <span className="px-4 text-[#06b6d4] text-xs">
              ◄──────────── TLS INSPECTION ────────────►
            </span>
            <div className="flex-1 h-px bg-gradient-to-r from-transparent via-[#06b6d4] to-transparent" />
          </div>

          <div className="bg-[#161616] border border-[#262626] p-4 mb-6">
            <div className="flex flex-wrap items-center gap-3 text-xs">
              <span className="text-[#8a8a8a] uppercase tracking-widest">Mirror</span>
              <span className={draft.enabled ? "text-[#10b981]" : "text-[#f43f5e]"}>
                ● {draft.enabled ? "ENABLED" : "DISABLED"}
              </span>
              <span className="text-[#4a4a4a]">|</span>
              <span className="text-[#8a8a8a]">Bypass domains:</span>
              <span className="text-[#06b6d4]">{bypassDomains.length}</span>
              <span className="text-[#4a4a4a]">|</span>
              <span className="text-[#8a8a8a]">Local exclusions:</span>
              <span className="text-[#06b6d4]">{exclusionStats.activeExclusions}</span>
              <span className="text-[#4a4a4a]">|</span>
              <span className="text-[#8a8a8a]">Mirror draft changes:</span>
              <span className={hasMirrorChanges ? "text-[#06b6d4]" : "text-[#4a4a4a]"}>
                {hasMirrorChanges ? "YES" : "NO"}
              </span>
            </div>
          </div>

          <div className="bg-[#161616] border border-[#262626] mb-6">
            <div className="flex overflow-x-auto border-b border-[#262626]">
              {tabs.map((tab) => (
                <button
                  key={tab.key}
                  type="button"
                  onClick={() => setActiveTab(tab.key)}
                  className={`px-4 py-3 text-sm whitespace-nowrap transition ${
                    activeTab === tab.key
                      ? "text-[#06b6d4] border-b-2 border-[#06b6d4]"
                      : "text-[#8a8a8a] hover:text-white"
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            {activeTab === "mirror" && (
              <div>
                <div className="flex flex-col gap-4 border-b border-[#262626] p-6 md:flex-row md:items-center md:justify-between">
                  <div>
                    <h1 className="text-2xl font-semibold tracking-normal">
                      Decryption Mirror
                    </h1>
                    <div className="mt-2 flex items-center gap-3 text-sm text-[#8a8a8a]">
                      <span className={draft.enabled ? "text-[#22c55e]" : "text-[#f97316]"}>
                        {draft.enabled ? "Enabled" : "Disabled"}
                      </span>
                      <span className="text-[#333]">|</span>
                      <span>{draft.targetHost || "no target"}:{draft.targetPort || 0}</span>
                    </div>
                  </div>

                  <label className="flex items-center gap-3 text-sm text-[#d4d4d4]">
                    <input
                      type="checkbox"
                      checked={draft.enabled}
                      onChange={(event) => updateDraft({ enabled: event.target.checked })}
                      className="h-5 w-5 accent-[#06b6d4]"
                    />
                    Mirror enabled
                  </label>
                </div>

                <div className="grid gap-6 p-6 md:grid-cols-2">
                  <label className="flex flex-col gap-2 text-sm">
                    <span className="text-[#8a8a8a]">Target host</span>
                    <input
                      value={draft.targetHost}
                      onChange={(event) => updateDraft({ targetHost: event.target.value })}
                      className="border border-[#333] bg-[#0f0f0f] px-3 py-2 text-[#f5f5f5] outline-none focus:border-[#06b6d4]"
                      placeholder="127.0.0.1"
                    />
                  </label>

                  <label className="flex flex-col gap-2 text-sm">
                    <span className="text-[#8a8a8a]">Target port</span>
                    <input
                      type="number"
                      min={0}
                      max={65535}
                      value={draft.targetPort}
                      onChange={(event) =>
                        updateDraft({ targetPort: Number(event.target.value) })
                      }
                      className="border border-[#333] bg-[#0f0f0f] px-3 py-2 text-[#f5f5f5] outline-none focus:border-[#06b6d4]"
                    />
                  </label>

                  <label className="flex items-center justify-between gap-4 border border-[#262626] bg-[#101010] px-4 py-3 text-sm">
                    <span>Client to server</span>
                    <input
                      type="checkbox"
                      checked={draft.includeClientToServer}
                      onChange={(event) =>
                        updateDraft({ includeClientToServer: event.target.checked })
                      }
                      className="h-5 w-5 accent-[#06b6d4]"
                    />
                  </label>

                  <label className="flex items-center justify-between gap-4 border border-[#262626] bg-[#101010] px-4 py-3 text-sm">
                    <span>Server to client</span>
                    <input
                      type="checkbox"
                      checked={draft.includeServerToClient}
                      onChange={(event) =>
                        updateDraft({ includeServerToClient: event.target.checked })
                      }
                      className="h-5 w-5 accent-[#06b6d4]"
                    />
                  </label>

                  <label className="flex items-center justify-between gap-4 border border-[#262626] bg-[#101010] px-4 py-3 text-sm">
                    <span>Forwarded only</span>
                    <input
                      type="checkbox"
                      checked={draft.forwardedOnly}
                      onChange={(event) =>
                        updateDraft({ forwardedOnly: event.target.checked })
                      }
                      className="h-5 w-5 accent-[#06b6d4]"
                    />
                  </label>

                  <label className="flex flex-col gap-2 text-sm">
                    <span className="text-[#8a8a8a]">Max session bytes</span>
                    <input
                      type="number"
                      min={1}
                      value={draft.maxSessionBytes}
                      onChange={(event) =>
                        updateDraft({ maxSessionBytes: Number(event.target.value) })
                      }
                      className="border border-[#333] bg-[#0f0f0f] px-3 py-2 text-[#f5f5f5] outline-none focus:border-[#06b6d4]"
                    />
                  </label>
                </div>

                <div className="flex flex-col gap-3 border-t border-[#262626] p-6 sm:flex-row sm:justify-end">
                  <button
                    type="button"
                    onClick={() => setDraft(cloneConfig(applied))}
                    disabled={!hasMirrorChanges || isSavingMirror}
                    className="inline-flex items-center justify-center gap-2 border border-[#333] px-4 py-2 text-sm text-[#d4d4d4] disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    <Icon icon="lucide:rotate-ccw" width={16} height={16} />
                    Reset
                  </button>
                  <button
                    type="button"
                    onClick={handleApplyMirror}
                    disabled={
                      !hasMirrorChanges ||
                      mirrorErrors.length > 0 ||
                      isMirrorLoading ||
                      isSavingMirror
                    }
                    className="inline-flex items-center justify-center gap-2 bg-[#06b6d4] px-4 py-2 text-sm font-medium text-[#061216] disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    <Icon icon="lucide:save" width={16} height={16} />
                    {isSavingMirror ? "Saving" : "Save"}
                  </button>
                </div>
              </div>
            )}

            {activeTab === "bypass" && (
              <div className="p-6">
                <div className="mb-6 flex flex-col gap-3 md:flex-row">
                  <label className="flex flex-1 flex-col gap-2 text-sm">
                    <span className="text-[#8a8a8a]">Domain</span>
                    <input
                      value={newBypassDomain}
                      onChange={(event) => setNewBypassDomain(event.target.value)}
                      className="border border-[#333] bg-[#0f0f0f] px-3 py-2 text-[#f5f5f5] outline-none focus:border-[#06b6d4]"
                      placeholder="www.google.com"
                    />
                  </label>
                  <div className="flex items-end">
                    <button
                      type="button"
                      onClick={handleCreateBypass}
                      disabled={!canCreateBypass}
                      className="inline-flex min-w-32 items-center justify-center gap-2 bg-[#06b6d4] px-4 py-2 text-sm font-medium text-[#061216] disabled:cursor-not-allowed disabled:opacity-40"
                    >
                      <Icon icon="lucide:plus" width={16} height={16} />
                      {isCreatingBypass ? "Adding" : "Add"}
                    </button>
                  </div>
                </div>

                <div className="overflow-x-auto border border-[#262626]">
                  <table className="w-full min-w-[680px] text-left text-sm">
                    <thead className="bg-[#101010] text-xs uppercase text-[#8a8a8a]">
                      <tr>
                        <th className="px-4 py-3 font-medium">Domain</th>
                        <th className="px-4 py-3 font-medium">Reason</th>
                        <th className="px-4 py-3 font-medium">Created</th>
                        <th className="px-4 py-3 text-right font-medium">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {bypassDomains.map((entry) => (
                        <tr key={entry.id} className="border-t border-[#262626]">
                          <td className="px-4 py-3 text-[#f5f5f5]">{entry.domain}</td>
                          <td className="px-4 py-3 text-[#8a8a8a]">{entry.reason}</td>
                          <td className="px-4 py-3 text-[#8a8a8a]">
                            {new Date(entry.createdAt).toLocaleString()}
                          </td>
                          <td className="px-4 py-3 text-right">
                            <button
                              type="button"
                              onClick={() => handleDeleteBypass(entry.id)}
                              disabled={isDeletingBypass || isCreatingBypass}
                              className="inline-flex items-center justify-center gap-2 border border-[#333] px-3 py-2 text-sm text-[#fda4af] disabled:cursor-not-allowed disabled:opacity-40"
                            >
                              <Icon icon="lucide:trash-2" width={16} height={16} />
                              Remove
                            </button>
                          </td>
                        </tr>
                      ))}
                      {!isBypassLoading && bypassDomains.length === 0 && (
                        <tr>
                          <td colSpan={4} className="px-4 py-8 text-center text-[#6a6a6a]">
                            No bypass domains configured.
                          </td>
                        </tr>
                      )}
                      {isBypassLoading && (
                        <tr>
                          <td colSpan={4} className="px-4 py-8 text-center text-[#6a6a6a]">
                            Loading bypass domains.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {activeTab === "exclusions" && (
              <div className="p-6">
                <div className="mb-6 grid gap-3 sm:grid-cols-3">
                  <div className="border border-[#262626] bg-[#101010] px-4 py-3">
                    <div className="text-xs uppercase text-[#8a8a8a]">Active</div>
                    <div className="mt-2 text-2xl font-semibold text-[#06b6d4]">
                      {exclusionStats.activeExclusions}
                    </div>
                  </div>
                  <div className="border border-[#262626] bg-[#101010] px-4 py-3">
                    <div className="text-xs uppercase text-[#8a8a8a]">Tracked failures</div>
                    <div className="mt-2 text-2xl font-semibold text-[#f5f5f5]">
                      {exclusionStats.trackedFailures}
                    </div>
                  </div>
                  <div className="flex items-end justify-start sm:justify-end">
                    <button
                      type="button"
                      onClick={handleClearExclusions}
                      disabled={isClearingExclusions || decryptionExclusions.length === 0}
                      className="inline-flex min-w-32 items-center justify-center gap-2 border border-[#333] px-4 py-2 text-sm text-[#fda4af] disabled:cursor-not-allowed disabled:opacity-40"
                    >
                      <Icon icon="lucide:trash-2" width={16} height={16} />
                      {isClearingExclusions ? "Clearing" : "Clear"}
                    </button>
                  </div>
                </div>

                <div className="overflow-x-auto border border-[#262626]">
                  <table className="w-full min-w-[860px] text-left text-sm">
                    <thead className="bg-[#101010] text-xs uppercase text-[#8a8a8a]">
                      <tr>
                        <th className="px-4 py-3 font-medium">Domain</th>
                        <th className="px-4 py-3 font-medium">Server</th>
                        <th className="px-4 py-3 font-medium">Reason</th>
                        <th className="px-4 py-3 font-medium">Failures</th>
                        <th className="px-4 py-3 font-medium">Last source</th>
                      </tr>
                    </thead>
                    <tbody>
                      {decryptionExclusions.map((entry) => (
                        <tr
                          key={`${entry.domain}-${entry.serverIp}-${entry.serverPort}`}
                          className="border-t border-[#262626]"
                        >
                          <td className="px-4 py-3 text-[#f5f5f5]">{entry.domain}</td>
                          <td className="px-4 py-3 text-[#8a8a8a]">
                            {entry.serverIp || "*"}:{entry.serverPort}
                          </td>
                          <td className="px-4 py-3 text-[#8a8a8a]">{entry.reason}</td>
                          <td className="px-4 py-3 text-[#f5f5f5]">{entry.failureCount}</td>
                          <td className="px-4 py-3 text-[#8a8a8a]">{entry.lastSourceIp}</td>
                        </tr>
                      ))}
                      {!isExclusionListLoading && decryptionExclusions.length === 0 && (
                        <tr>
                          <td colSpan={5} className="px-4 py-8 text-center text-[#6a6a6a]">
                            No local exclusions.
                          </td>
                        </tr>
                      )}
                      {isExclusionListLoading && (
                        <tr>
                          <td colSpan={5} className="px-4 py-8 text-center text-[#6a6a6a]">
                            Loading local exclusions.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>

          {uiErrors.length > 0 && (
            <div className="mb-6 border border-[#3f1d24] bg-[#190f12] px-6 py-4 text-sm text-[#fda4af]">
              {uiErrors.map((error) => (
                <div key={error}>{error}</div>
              ))}
            </div>
          )}

          <div className="text-center text-xs text-[#4a4a4a]">
            TLS inspection module
            <span className="text-[#06b6d4] mx-3">|</span>
            Mirror, bypass, and local exclusion controls
            <span className="text-[#06b6d4] mx-3">|</span>
            RaptorGate UI
          </div>
        </div>
      </div>
    </div>
  );
}
