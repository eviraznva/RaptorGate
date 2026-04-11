import { status } from '@grpc/grpc-js';
import { Controller, Inject, Logger } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { GetActiveConfigUseCase } from 'src/application/use-cases/get-active-config.use-case';
import { EntityNotFoundException } from 'src/domain/exceptions/entity-not-found-exception';
import {
  FirewallConfigSnapshotServiceController,
  FirewallConfigSnapshotServiceControllerMethods,
  PushActiveConfigSnapshotRequest,
  PushActiveConfigSnapshotResponse,
} from './generated/services/config_snapshot_service';

@Controller()
@FirewallConfigSnapshotServiceControllerMethods()
export class RaptorGateController implements FirewallConfigSnapshotServiceController {
  private readonly logger = new Logger(RaptorGateController.name);

  private static readonly ALLOWED_REASONS = new Set([
    'apply',
    'rollback',
    'manual_sync',
  ]);

  private static readonly ALLOWED_SNAPSHOT_TYPES = new Set([
    'manual_import',
    'rollback_point',
    'auto_save',
  ]);

  constructor(
    @Inject(GetActiveConfigUseCase)
    private readonly getActiveConfigUseCase: GetActiveConfigUseCase,
  ) {}

  async pushActiveConfigSnapshot(
    request: PushActiveConfigSnapshotRequest,
  ): Promise<PushActiveConfigSnapshotResponse> {
    const correlationId = this.normalize(request.correlationId);

    try {
      const snapshot = request.snapshot;
      if (!snapshot) {
        return this.reject(correlationId, 'Missing snapshot payload');
      }

      const reason = this.normalize(request.reason).toLowerCase();
      if (!this.isAllowedReason(reason)) {
        return this.reject(correlationId, 'Invalid reason');
      }

      if (!this.isUuid(snapshot.id)) {
        return this.reject(correlationId, 'Invalid snapshot id');
      }

      if (!this.isUuid(snapshot.createdBy)) {
        return this.reject(correlationId, 'Invalid createdBy');
      }

      if (
        !Number.isInteger(snapshot.versionNumber) ||
        snapshot.versionNumber < 1
      ) {
        return this.reject(correlationId, 'Invalid versionNumber');
      }

      if (!this.isAllowedSnapshotType(snapshot.snapshotType)) {
        return this.reject(correlationId, 'Invalid snapshotType');
      }

      if (!this.isSha256(snapshot.checksum)) {
        return this.reject(correlationId, 'Invalid checksum format');
      }

      if (!snapshot.bundle) {
        return this.reject(correlationId, 'Missing bundle');
      }

      try {
        const active = await this.getActiveConfigUseCase.execute();
        const sameId = active.getId() === snapshot.id;
        const sameVerAndChecksum =
          active.getVersionNumber() === snapshot.versionNumber &&
          active.getChecksum().getValue().toLowerCase() ===
            snapshot.checksum.toLowerCase();

        if (sameId || sameVerAndChecksum) {
          return {
            correlationId,
            accepted: true,
            message: 'Snapshot already active',
            appliedSnapshotId: snapshot.id,
          };
        }
      } catch (error) {
        if (!(error instanceof EntityNotFoundException)) {
          throw error;
        }
      }

      this.logger.log(
        `[PushActiveConfigSnapshot] correlationId=${correlationId}
reason=${reason} snapshotId=${snapshot.id} version=${snapshot.versionNumber}`,
      );

      return {
        correlationId,
        accepted: true,
        message: 'Snapshot validated',
        appliedSnapshotId: snapshot.id,
      };
    } catch (error) {
      this.logger.error(
        `[PushActiveConfigSnapshot] failed correlationId=${correlationId}`,
        error instanceof Error ? error.stack : undefined,
      );

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Failed to process pushed config snapshot',
      });
    }
  }

  private reject(
    correlationId: string,
    message: string,
  ): PushActiveConfigSnapshotResponse {
    return {
      correlationId,
      accepted: false,
      message,
      appliedSnapshotId: '',
    };
  }

  private isAllowedReason(reason: string): boolean {
    return RaptorGateController.ALLOWED_REASONS.has(reason);
  }

  private isAllowedSnapshotType(type: string): boolean {
    return RaptorGateController.ALLOWED_SNAPSHOT_TYPES.has(type);
  }

  private isUuid(value: string): boolean {
    return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      value,
    );
  }

  private isSha256(value: string): boolean {
    return /^[a-f0-9]{64}$/i.test(value);
  }

  private normalize(value: string | null | undefined): string {
    return value?.trim() ?? '';
  }
}
