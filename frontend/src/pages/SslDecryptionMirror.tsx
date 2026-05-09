import { useEffect, useMemo, useState } from "react";
import { Icon } from "@iconify/react";
import {
  useGetDecryptionMirrorConfigQuery,
  useUpdateDecryptionMirrorConfigMutation,
} from "../services/decryptionMirror";
import type { ApiFailure, ApiSuccess } from "../types/ApiResponse";
import {
  defaultDecryptionMirrorConfig,
  type DecryptionMirrorConfig,
  type DecryptionMirrorPayload,
} from "../types/ssl/DecryptionMirror";

function cloneConfig(config: DecryptionMirrorConfig): DecryptionMirrorConfig {
  return JSON.parse(JSON.stringify(config)) as DecryptionMirrorConfig;
}

function validateConfig(config: DecryptionMirrorConfig): string[] {
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

export default function SslDecryptionMirror() {
  const [draft, setDraft] = useState<DecryptionMirrorConfig>(
    cloneConfig(defaultDecryptionMirrorConfig),
  );
  const [applied, setApplied] = useState<DecryptionMirrorConfig>(
    cloneConfig(defaultDecryptionMirrorConfig),
  );
  const [requestError, setRequestError] = useState<string | null>(null);

  const { data, isLoading, isError } = useGetDecryptionMirrorConfigQuery();
  const [updateConfig, { isLoading: isSaving }] =
    useUpdateDecryptionMirrorConfigMutation();

  useEffect(() => {
    if (!data) {
      return;
    }

    const payload = (data as ApiSuccess<DecryptionMirrorPayload>).data
      .decryptionMirror;

    setRequestError(null);
    setDraft(cloneConfig(payload));
    setApplied(cloneConfig(payload));
  }, [data]);

  const errors = useMemo(() => validateConfig(draft), [draft]);
  const uiErrors = useMemo(() => {
    const next = [...errors];

    if (isError) {
      next.unshift("SSL mirror: failed to load config from backend.");
    }

    if (requestError) {
      next.unshift(`SSL mirror: ${requestError}`);
    }

    return next;
  }, [errors, isError, requestError]);

  const hasChanges = useMemo(
    () => JSON.stringify(draft) !== JSON.stringify(applied),
    [draft, applied],
  );

  const updateDraft = (partial: Partial<DecryptionMirrorConfig>) => {
    setDraft((current) => ({
      ...current,
      ...partial,
    }));
  };

  const handleApply = async () => {
    try {
      setRequestError(null);
      const response = await updateConfig({
        ...draft,
        targetHost: draft.targetHost.trim(),
      }).unwrap();
      const payload = (response as ApiSuccess<DecryptionMirrorPayload>).data
        .decryptionMirror;

      setDraft(cloneConfig(payload));
      setApplied(cloneConfig(payload));
    } catch (error) {
      setRequestError((error as ApiFailure).message);
    }
  };

  return (
    <div className="min-h-screen bg-[#0c0c0c] flex flex-col text-[#f5f5f5]">
      <div className="flex-1 flex justify-center p-8">
        <div className="w-full max-w-5xl">
          <div className="flex items-center justify-center mb-8">
            <div className="flex-1 h-px bg-gradient-to-r from-transparent via-[#06b6d4] to-transparent" />
            <span className="px-4 text-[#06b6d4] text-xs">
              ◄──────────── SSL DECRYPTION MIRROR ────────────►
            </span>
            <div className="flex-1 h-px bg-gradient-to-r from-transparent via-[#06b6d4] to-transparent" />
          </div>

          <div className="bg-[#161616] border border-[#262626]">
            <div className="flex flex-col gap-4 border-b border-[#262626] p-6 md:flex-row md:items-center md:justify-between">
              <div>
                <h1 className="text-2xl font-semibold tracking-normal">
                  SSL Decryption Mirror
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

            {uiErrors.length > 0 && (
              <div className="border-t border-[#262626] bg-[#190f12] px-6 py-4 text-sm text-[#fda4af]">
                {uiErrors.map((error) => (
                  <div key={error}>{error}</div>
                ))}
              </div>
            )}

            <div className="flex flex-col gap-3 border-t border-[#262626] p-6 sm:flex-row sm:justify-end">
              <button
                type="button"
                onClick={() => setDraft(cloneConfig(applied))}
                disabled={!hasChanges || isSaving}
                className="inline-flex items-center justify-center gap-2 border border-[#333] px-4 py-2 text-sm text-[#d4d4d4] disabled:cursor-not-allowed disabled:opacity-40"
              >
                <Icon icon="lucide:rotate-ccw" width={16} height={16} />
                Reset
              </button>
              <button
                type="button"
                onClick={handleApply}
                disabled={!hasChanges || errors.length > 0 || isLoading || isSaving}
                className="inline-flex items-center justify-center gap-2 bg-[#06b6d4] px-4 py-2 text-sm font-medium text-[#061216] disabled:cursor-not-allowed disabled:opacity-40"
              >
                <Icon icon="lucide:save" width={16} height={16} />
                {isSaving ? "Saving" : "Save"}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
