import {
  Inject,
  Injectable,
  Logger,
  OnModuleInit,
  ServiceUnavailableException,
} from '@nestjs/common';
import type { ClientGrpc } from '@nestjs/microservices';
import { firstValueFrom } from 'rxjs';
import type {
  IIdentitySessionSyncService,
  IdentitySessionSyncPayload,
} from '../../application/ports/identity-session-sync-service.interface.js';
import type { Timestamp } from '../grpc/generated/google/protobuf/timestamp.js';
import {
  IDENTITY_SESSION_SERVICE_NAME,
  type IdentitySessionServiceClient,
} from '../grpc/generated/services/identity_session_service.js';

export const IDENTITY_SESSION_SYNC_GRPC_CLIENT_TOKEN =
  'IDENTITY_SESSION_SYNC_GRPC_CLIENT_TOKEN';

@Injectable()
export class GrpcIdentitySessionSyncService
  implements IIdentitySessionSyncService, OnModuleInit
{
  private readonly logger = new Logger(GrpcIdentitySessionSyncService.name);
  private identitySessionClient: IdentitySessionServiceClient;

  constructor(
    @Inject(IDENTITY_SESSION_SYNC_GRPC_CLIENT_TOKEN)
    private readonly grpcClient: ClientGrpc,
  ) {}

  onModuleInit(): void {
    this.identitySessionClient =
      this.grpcClient.getService<IdentitySessionServiceClient>(
        IDENTITY_SESSION_SERVICE_NAME,
      );
  }

  async upsertIdentitySession(
    session: IdentitySessionSyncPayload,
  ): Promise<void> {
    this.logger.log({
      event: 'firewall.identity_session.upsert.started',
      message: 'pushing identity session upsert to firewall',
      sessionId: session.id,
      ipAddress: session.ipAddress,
    });

    try {
      await firstValueFrom(
        this.identitySessionClient.upsertIdentitySession({
          session: {
            id: session.id,
            identityUserId: session.identityUserId,
            radiusUsername: session.radiusUsername,
            macAddress: session.macAddress,
            ipAddress: session.ipAddress,
            nasIp: session.nasIp,
            calledStationId: session.calledStationId,
            authenticatedAt: this.toTimestamp(session.authenticatedAt),
            expiresAt: this.toTimestamp(session.expiresAt),
            groups: session.groups,
          },
        }),
      );

      this.logger.log({
        event: 'firewall.identity_session.upsert.succeeded',
        message: 'firewall accepted identity session upsert',
        sessionId: session.id,
        ipAddress: session.ipAddress,
      });
    } catch (error) {
      const reason =
        error instanceof Error ? error.message : 'Unknown gRPC error';

      this.logger.error(
        {
          event: 'firewall.identity_session.upsert.failed',
          message: 'failed to upsert identity session on firewall',
          sessionId: session.id,
          ipAddress: session.ipAddress,
          error: reason,
        },
        error instanceof Error ? error.stack : undefined,
      );

      throw new ServiceUnavailableException(
        `Firewall identity session sync is unavailable. ${reason}`,
      );
    }
  }

  async revokeIdentitySession(ipAddress: string): Promise<boolean> {
    this.logger.log({
      event: 'firewall.identity_session.revoke.started',
      message: 'pushing identity session revoke to firewall',
      ipAddress,
    });

    try {
      const response = await firstValueFrom(
        this.identitySessionClient.revokeIdentitySession({ ipAddress }),
      );

      this.logger.log({
        event: 'firewall.identity_session.revoke.succeeded',
        message: 'firewall processed identity session revoke',
        ipAddress,
        removed: response.removed,
      });

      return response.removed;
    } catch (error) {
      const reason =
        error instanceof Error ? error.message : 'Unknown gRPC error';

      this.logger.error(
        {
          event: 'firewall.identity_session.revoke.failed',
          message: 'failed to revoke identity session on firewall',
          ipAddress,
          error: reason,
        },
        error instanceof Error ? error.stack : undefined,
      );

      throw new ServiceUnavailableException(
        `Firewall identity session sync is unavailable. ${reason}`,
      );
    }
  }

  private toTimestamp(date: Date): Timestamp {
    const ms = date.getTime();
    return {
      seconds: Math.floor(ms / 1000),
      nanos: (ms % 1000) * 1_000_000,
    };
  }
}
