import {
  Inject,
  Injectable,
  OnModuleInit,
  ServiceUnavailableException,
} from '@nestjs/common';
import type { ClientGrpc } from '@nestjs/microservices';
import { firstValueFrom } from 'rxjs';
import type {
  IDecryptionExclusionObservabilityService,
  LocalDecryptionExclusion,
  LocalDecryptionExclusionDetail,
  LocalDecryptionExclusionStats,
} from '../../application/ports/pinning-observability-service.interface.js';
import {
  FIREWALL_QUERY_SERVICE_NAME,
  type FirewallQueryServiceClient,
  type LocalDecryptionExclusion as ProtoLocalDecryptionExclusion,
} from '../grpc/generated/services/query_service.js';

export const PINNING_OBSERVABILITY_GRPC_CLIENT_TOKEN =
  'PINNING_OBSERVABILITY_GRPC_CLIENT_TOKEN';

@Injectable()
export class GrpcDecryptionExclusionObservabilityService
  implements IDecryptionExclusionObservabilityService, OnModuleInit
{
  private client: FirewallQueryServiceClient;

  constructor(
    @Inject(PINNING_OBSERVABILITY_GRPC_CLIENT_TOKEN)
    private readonly grpcClient: ClientGrpc,
  ) {}

  onModuleInit(): void {
    this.client = this.grpcClient.getService<FirewallQueryServiceClient>(
      FIREWALL_QUERY_SERVICE_NAME,
    );
  }

  async getStats(): Promise<LocalDecryptionExclusionStats> {
    try {
      const response = await firstValueFrom(
        this.client.getLocalDecryptionExclusionStats({}),
      );
      return {
        activeExclusions: Number(response.activeExclusions),
        trackedFailures: Number(response.trackedFailures),
      };
    } catch (error) {
      const reason =
        error instanceof Error ? error.message : 'Unknown gRPC error';
      throw new ServiceUnavailableException(
        `Firewall query service is unavailable. ${reason}`,
      );
    }
  }

  async getExclusion(
    domain: string,
    serverIp?: string,
    serverPort?: number,
  ): Promise<LocalDecryptionExclusionDetail> {
    try {
      const response = await firstValueFrom(
        this.client.getLocalDecryptionExclusion({
          domain,
          serverIp: serverIp ?? '',
          serverPort: serverPort ?? 0,
        }),
      );
      return {
        found: response.found,
        exclusion: response.exclusion
          ? this.toLocalDecryptionExclusion(response.exclusion)
          : undefined,
      };
    } catch (error) {
      const reason =
        error instanceof Error ? error.message : 'Unknown gRPC error';
      throw new ServiceUnavailableException(
        `Firewall query service is unavailable. ${reason}`,
      );
    }
  }

  async listExclusions(): Promise<LocalDecryptionExclusion[]> {
    try {
      const response = await firstValueFrom(
        this.client.listLocalDecryptionExclusions({}),
      );
      return response.exclusions.map((entry) =>
        this.toLocalDecryptionExclusion(entry),
      );
    } catch (error) {
      const reason =
        error instanceof Error ? error.message : 'Unknown gRPC error';
      throw new ServiceUnavailableException(
        `Firewall query service is unavailable. ${reason}`,
      );
    }
  }

  async clearExclusions(): Promise<{ removed: number }> {
    try {
      const response = await firstValueFrom(
        this.client.clearLocalDecryptionExclusions({}),
      );
      return { removed: Number(response.removed) };
    } catch (error) {
      const reason =
        error instanceof Error ? error.message : 'Unknown gRPC error';
      throw new ServiceUnavailableException(
        `Firewall query service is unavailable. ${reason}`,
      );
    }
  }

  private toLocalDecryptionExclusion(
    entry: ProtoLocalDecryptionExclusion,
  ): LocalDecryptionExclusion {
    return {
      domain: entry.domain,
      serverIp: entry.serverIp,
      serverPort: Number(entry.serverPort),
      reason: entry.reason,
      failureCount: Number(entry.failureCount),
      lastSourceIp: entry.lastSourceIp,
    };
  }
}
