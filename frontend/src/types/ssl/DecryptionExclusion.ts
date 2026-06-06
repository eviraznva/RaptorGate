export interface LocalDecryptionExclusion {
  domain: string;
  serverIp: string;
  serverPort: number;
  reason: string;
  failureCount: number;
  lastSourceIp: string;
}

export interface DecryptionExclusionStatsPayload {
  activeExclusions: number;
  trackedFailures: number;
}

export interface DecryptionExclusionListPayload {
  exclusions: LocalDecryptionExclusion[];
}

export interface ClearDecryptionExclusionsPayload {
  removed: number;
}
