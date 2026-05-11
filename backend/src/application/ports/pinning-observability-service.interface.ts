export interface PinningStats {
  activeBypasses: number;
  trackedFailures: number;
}

export interface PinningBypassDetail {
  found: boolean;
  reason: string;
  failureCount: number;
}

export interface IPinningObservabilityService {
  getStats(): Promise<PinningStats>;
  getBypass(sourceIp: string, domain: string): Promise<PinningBypassDetail>;
}

export const PINNING_OBSERVABILITY_SERVICE_TOKEN = Symbol(
  'PINNING_OBSERVABILITY_SERVICE_TOKEN',
);
