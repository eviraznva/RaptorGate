import { ApiProperty } from '@nestjs/swagger';
import type { TcpTrackedSessionState } from '../../domain/entities/tcp-tracked-session.entity.js';
import { TcpSessionEndpointResponseDto } from './tcp-session-endpoint-response.dto.js';

export class TcpTrackedSessionItemResponseDto {
  @ApiProperty({ type: () => TcpSessionEndpointResponseDto })
  endpointA: TcpSessionEndpointResponseDto;

  @ApiProperty({ type: () => TcpSessionEndpointResponseDto })
  endpointB: TcpSessionEndpointResponseDto;

  @ApiProperty({
    example: 'established',
    enum: [
      'unspecified',
      'syn_sent',
      'syn_ack_received',
      'established',
      'fin_sent',
      'ack_sent',
      'ack_fin_sent',
      'time_wait',
      'closed',
      'unknown',
    ],
  })
  state: TcpTrackedSessionState;
}
