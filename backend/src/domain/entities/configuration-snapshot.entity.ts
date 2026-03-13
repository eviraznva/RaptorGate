import { SnapshotType } from '../value-objects/snapshot-type.vo';
import { Checksum } from '../value-objects/checksum.vo';

export class ConfigurationSnapshot {
  private constructor(
    private readonly id: string,
    private versionNumber: number,
    private snapshotType: SnapshotType,
    private checksum: Checksum,
    private isActive: boolean,
    private payloadJson: string,
    private changesSummary: string | null,
    private readonly createdAt: Date,
  ) {}

  public static create(
    id: string,
    versionNumber: number,
    snapshotType: SnapshotType,
    checksum: Checksum,
    isActive: boolean,
    payloadJson: string,
    changesSummary: string | null,
    createdAt: Date,
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

  public getPayloadJson(): string {
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
}
