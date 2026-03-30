export class RollbackConfigSnapshotResponseDto {
  id: string;
  versionNumber: number;
  snapshotType: string;
  checksum: string;
  isActive: boolean;
  payloadJson: unknown;
  changesSummary: string | null;
  createdAt: Date;
  createdBy: string;
}
