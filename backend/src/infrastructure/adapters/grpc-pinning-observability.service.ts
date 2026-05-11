import {
  Inject,
  Injectable,
  OnModuleInit,
  ServiceUnavailableException,
} from '@nestjs/common';
import type { ClientGrpc } from '@nestjs/microservices';
import { firstValueFrom } from 'rxjs';
import type {
  IPinningObservabilityService,
  PinningBypassDetail,
  PinningStats,
} from '../../application/ports/pinning-observability-service.interface.js';
import {
  FIREWALL_QUERY_SERVICE_NAME,
  type FirewallQueryServiceClient,
} from '../grpc/generated/services/query_service.js';

export const PINNING_OBSERVABILITY_GRPC_CLIENT_TOKEN =
  'PINNING_OBSERVABILITY_GRPC_CLIENT_TOKEN';

@Injectable()
export class GrpcPinningObservabilityService
  implements IPinningObservabilityService, OnModuleInit
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

  async getStats(): Promise<PinningStats> {
    try {
      const response = await firstValueFrom(this.client.getPinningStats({}));
      return {
        activeBypasses: Number(response.activeBypasses),
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

  async getBypass(
    sourceIp: string,
    domain: string,
  ): Promise<PinningBypassDetail> {
    try {
      const response = await firstValueFrom(
        this.client.getPinningBypass({ sourceIp, domain }),
      );
      return {
        found: response.found,
        reason: response.reason,
        failureCount: response.failureCount,
      };
    } catch (error) {
      const reason =
        error instanceof Error ? error.message : 'Unknown gRPC error';
      throw new ServiceUnavailableException(
        `Firewall query service is unavailable. ${reason}`,
      );
    }
  }
}
