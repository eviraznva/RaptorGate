export type DefaultPolicy = "ALLOW" | "DROP";

export interface ZonePair {
  id: string;
  srcZoneId: string;
  dstZoneId: string;
  defaultPolicy: DefaultPolicy;
  createdAt: string;
  createdBy: string;
}
