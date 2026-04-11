export class ImportConfigDto {
  accessToken: string;
  snapshotData: {
    id: string;
    versionNumber: number;
    snapshotType: string;
    checksum: string;
    isActive: boolean;
    payloadJson: unknown;
    changeSummary: string | null;
    createdAt: string;
    createdBy: string;
  };
}
