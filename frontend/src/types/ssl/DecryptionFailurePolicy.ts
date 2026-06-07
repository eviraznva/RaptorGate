export type DecryptionFailurePolicyAction = "block" | "cacheAndBypass";

export interface DecryptionFailurePolicy {
  enabled: boolean;
  failureThreshold: number;
  failureWindowSec: number;
  localExclusionTtlSec: number;
  maxEntries: number;
  action: DecryptionFailurePolicyAction;
}

export type DecryptionFailurePolicyPayload = {
  decryptionFailurePolicy: DecryptionFailurePolicy;
};

export const defaultDecryptionFailurePolicy: DecryptionFailurePolicy = {
  enabled: true,
  failureThreshold: 3,
  failureWindowSec: 60,
  localExclusionTtlSec: 86400,
  maxEntries: 4096,
  action: "block",
};
