export interface LocalDecryptionExclusionStats {
  activeExclusions: number;
  trackedFailures: number;
}

export interface LocalDecryptionExclusion {
  domain: string;
  serverIp: string;
  serverPort: number;
  reason: string;
  failureCount: number;
  lastSourceIp: string;
}

export interface LocalDecryptionExclusionDetail {
  found: boolean;
  exclusion?: LocalDecryptionExclusion;
}

export interface IDecryptionExclusionObservabilityService {
  getStats(): Promise<LocalDecryptionExclusionStats>;
  getExclusion(
    domain: string,
    serverIp?: string,
    serverPort?: number,
  ): Promise<LocalDecryptionExclusionDetail>;
  listExclusions(): Promise<LocalDecryptionExclusion[]>;
  clearExclusions(): Promise<{ removed: number }>;
}

export type IPinningObservabilityService =
  IDecryptionExclusionObservabilityService;

export const PINNING_OBSERVABILITY_SERVICE_TOKEN = Symbol(
  'PINNING_OBSERVABILITY_SERVICE_TOKEN',
);
