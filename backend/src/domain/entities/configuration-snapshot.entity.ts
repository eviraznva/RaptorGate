import { ConfigSnapshotPayload } from '../value-objects/config-snapshot-payload.interface';
import { SnapshotType } from '../value-objects/snapshot-type.vo';
import { Checksum } from '../value-objects/checksum.vo';

export class ConfigurationSnapshot {
  private constructor(
    private readonly id: string,
    private versionNumber: number,
    private snapshotType: SnapshotType,
    private checksum: Checksum,
    private isActive: boolean,
    private payloadJson: unknown,
    private changesSummary: string | null,
    private readonly createdAt: Date,
    private readonly createdBy: string,
  ) {}

  public static create(
    id: string,
    versionNumber: number,
    snapshotType: SnapshotType,
    checksum: Checksum,
    isActive: boolean,
    payloadJson: unknown,
    changesSummary: string | null,
    createdAt: Date,
    createdBy: string,
  ): ConfigurationSnapshot {
    return new ConfigurationSnapshot(
      id,
      versionNumber,
      snapshotType,
      checksum,
      isActive,
      payloadJson,
      changesSummary,
      createdAt,
      createdBy,
    );
  }

  public getId(): string {
    return this.id;
  }

  public getVersionNumber(): number {
    return this.versionNumber;
  }

  public getSnapshotType(): SnapshotType {
    return this.snapshotType;
  }

  public getChecksum(): Checksum {
    return this.checksum;
  }

  public getIsActive(): boolean {
    return this.isActive;
  }

  public getPayloadJson(): unknown {
    return this.payloadJson;
  }

  public getChangesSummary(): string | null {
    return this.changesSummary;
  }

  public getCreatedAt(): Date {
    return this.createdAt;
  }

  public setIsActive(isActive: boolean): void {
    this.isActive = isActive;
  }

  public setChangesSummary(changesSummary: string): void {
    this.changesSummary = changesSummary;
  }

  public getCreatedBy(): string {
    return this.createdBy;
  }

  public deserializePayload(): ConfigSnapshotPayload {
    const obj: unknown =
      typeof this.payloadJson === 'string'
        ? JSON.parse(this.payloadJson)
        : this.payloadJson;

    if (obj === null || typeof obj !== 'object') {
      throw new Error(
        'Invalid configuration snapshot payload: expected a JSON object.',
      );
    }

    return obj as ConfigSnapshotPayload;
  }
}
