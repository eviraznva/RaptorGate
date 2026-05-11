export type SnapshotType = "manual_import" | "rollback_point" | "auto_save";

export type ConfigSnapshot = {
  id: string;
  versionNumber: number;
  snapshotType: SnapshotType;
  checksum: string;
  isActive: boolean;
  payloadJson: Record<string, unknown>;
  changeSummary: string | null;
  createdAt: string;
  createdBy: string;
};
