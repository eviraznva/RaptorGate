import {
  Inject,
  Injectable,
  OnModuleInit,
  ServiceUnavailableException,
} from '@nestjs/common';
import type { ClientGrpc } from '@nestjs/microservices';
import { firstValueFrom } from 'rxjs';
import type { IFirewallTcpSessionsQueryService } from '../../application/ports/firewall-tcp-sessions-query-service.interface.js';
import {
  TcpSessionEndpoint,
  TcpTrackedSession,
  type TcpTrackedSessionState,
} from '../../domain/entities/tcp-tracked-session.entity.js';
import { IpAddress } from '../../domain/value-objects/ip-address.vo.js';
import { Port } from '../../domain/value-objects/port.vo.js';
import {
  FIREWALL_QUERY_SERVICE_NAME,
  type FirewallQueryServiceClient,
  type TcpSessionEndpoint as GrpcTcpSessionEndpoint,
  type TcpTrackedSession as GrpcTcpTrackedSession,
  TcpTrackedSessionState as GrpcTcpTrackedSessionState,
} from '../grpc/generated/services/query_service.js';

export const FIREWALL_TCP_SESSIONS_GRPC_CLIENT_TOKEN =
  'FIREWALL_TCP_SESSIONS_GRPC_CLIENT_TOKEN';

@Injectable()
export class GrpcFirewallTcpSessionsQueryService
  implements IFirewallTcpSessionsQueryService, OnModuleInit
{
  private firewallQueryClient: FirewallQueryServiceClient;

  constructor(
    @Inject(FIREWALL_TCP_SESSIONS_GRPC_CLIENT_TOKEN)
    private readonly grpcClient: ClientGrpc,
  ) {}

  onModuleInit(): void {
    this.firewallQueryClient =
      this.grpcClient.getService<FirewallQueryServiceClient>(
        FIREWALL_QUERY_SERVICE_NAME,
      );
  }

  async getTcpSessions(): Promise<TcpTrackedSession[]> {
    try {
      const response = await firstValueFrom(
        this.firewallQueryClient.getTcpSessions({}),
      );

      return response.sessions.map((session) =>
        this.toTcpTrackedSessionEntity(session),
      );
    } catch (error) {
      const reason =
        error instanceof Error ? error.message : 'Unknown gRPC error';

      throw new ServiceUnavailableException(
        `Firewall query service failed to get TCP sessions. ${reason}`,
      );
    }
  }

  private toTcpTrackedSessionEntity(
    session: GrpcTcpTrackedSession,
  ): TcpTrackedSession {
    if (!session.endpointA || !session.endpointB) {
      throw new ServiceUnavailableException(
        'Firewall query service returned TCP session without endpoints.',
      );
    }

    return TcpTrackedSession.create(
      this.toTcpSessionEndpointEntity(session.endpointA),
      this.toTcpSessionEndpointEntity(session.endpointB),
      this.toTcpTrackedSessionState(session.state),
    );
  }

  private toTcpSessionEndpointEntity(
    endpoint: GrpcTcpSessionEndpoint,
  ): TcpSessionEndpoint {
    return TcpSessionEndpoint.create(
      IpAddress.create(endpoint.ip),
      Port.create(endpoint.port),
    );
  }

  private toTcpTrackedSessionState(
    state: GrpcTcpTrackedSessionState,
  ): TcpTrackedSessionState {
    switch (state) {
      case GrpcTcpTrackedSessionState.TCP_TRACKED_SESSION_STATE_SYN_SENT:
        return 'syn_sent';
      case GrpcTcpTrackedSessionState.TCP_TRACKED_SESSION_STATE_SYN_ACK_RECEIVED:
        return 'syn_ack_received';
      case GrpcTcpTrackedSessionState.TCP_TRACKED_SESSION_STATE_ESTABLISHED:
        return 'established';
      case GrpcTcpTrackedSessionState.TCP_TRACKED_SESSION_STATE_FIN_SENT:
        return 'fin_sent';
      case GrpcTcpTrackedSessionState.TCP_TRACKED_SESSION_STATE_ACK_SENT:
        return 'ack_sent';
      case GrpcTcpTrackedSessionState.TCP_TRACKED_SESSION_STATE_ACK_FIN_SENT:
        return 'ack_fin_sent';
      case GrpcTcpTrackedSessionState.TCP_TRACKED_SESSION_STATE_TIME_WAIT:
        return 'time_wait';
      case GrpcTcpTrackedSessionState.TCP_TRACKED_SESSION_STATE_CLOSED:
        return 'closed';
      case GrpcTcpTrackedSessionState.UNRECOGNIZED:
        return 'unknown';
      case GrpcTcpTrackedSessionState.TCP_TRACKED_SESSION_STATE_UNSPECIFIED:
      default:
        return 'unspecified';
    }
  }
}
