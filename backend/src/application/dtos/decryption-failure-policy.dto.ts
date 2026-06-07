export type DecryptionFailurePolicyActionDto = 'block' | 'cacheAndBypass';

export interface DecryptionFailurePolicyDto {
  enabled: boolean;
  failureThreshold: number;
  failureWindowSec: number;
  localExclusionTtlSec: number;
  maxEntries: number;
  action: DecryptionFailurePolicyActionDto;
}

export interface DecryptionFailurePolicyResponseDto {
  decryptionFailurePolicy: DecryptionFailurePolicyDto;
}
