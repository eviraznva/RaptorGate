import {
  TcpSessionEndpoint,
  TcpTrackedSession,
} from '../../domain/entities/tcp-tracked-session.entity.js';
import { TcpSessionEndpointResponseDto } from '../dtos/tcp-session-endpoint-response.dto.js';
import { TcpTrackedSessionItemResponseDto } from '../dtos/tcp-tracked-session-item-response.dto.js';

export class TcpTrackedSessionResponseMapper {
  static toDto(
    tcpTrackedSession: TcpTrackedSession,
  ): TcpTrackedSessionItemResponseDto {
    return {
      endpointA: this.endpointToDto(tcpTrackedSession.getEndpointA()),
      endpointB: this.endpointToDto(tcpTrackedSession.getEndpointB()),
      state: tcpTrackedSession.getState(),
    };
  }

  private static endpointToDto(
    endpoint: TcpSessionEndpoint,
  ): TcpSessionEndpointResponseDto {
    return {
      ip: endpoint.getIpAddress().getValue,
      port: endpoint.getPort().getValue,
    };
  }
}
