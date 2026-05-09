import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import type {
  TcpTrackedSessionDestroyReason,
  TcpTrackedSessionDirection,
  TcpTrackedSessionInterfaces,
  TcpTrackedSessionLifecycle,
  TcpTrackedSessionNatInfo,
  TcpTrackedSessionState,
} from '../../domain/entities/tcp-tracked-session.entity.js';
import { TcpSessionEndpointResponseDto } from './tcp-session-endpoint-response.dto.js';

export class TcpTrackedSessionItemResponseDto {
  @ApiProperty({ example: '42' })
  id: string;

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

  @ApiProperty({ example: 'active', enum: ['active', 'destroyed', 'unspecified'] })
  lifecycle: TcpTrackedSessionLifecycle;

  @ApiProperty({ example: 'reply', enum: ['original', 'reply', 'unspecified'] })
  lastDirection: TcpTrackedSessionDirection;

  @ApiProperty({
    example: {
      originalIngress: 'eth0',
      originalEgress: 'tun0',
      replyIngress: 'tun0',
      replyEgress: 'eth0',
    },
  })
  interfaces: TcpTrackedSessionInterfaces;

  @ApiProperty({ example: 7 })
  mark: number;

  @ApiProperty({ example: 10 })
  statusBits: number;

  @ApiProperty({ example: 1000 })
  bytesOriginal: number;

  @ApiProperty({ example: 2000 })
  bytesReply: number;

  @ApiProperty({ example: 3 })
  packetsOriginal: number;

  @ApiProperty({ example: 4 })
  packetsReply: number;

  @ApiProperty({ example: '2026-05-09T10:00:00.000Z' })
  createdAt: string;

  @ApiProperty({ example: '2026-05-09T10:00:05.000Z' })
  lastSeenAt: string;

  @ApiProperty({ example: '2026-05-09T10:01:00.000Z' })
  expiresAt: string;

  @ApiPropertyOptional({ example: '2026-05-09T10:01:00.000Z' })
  destroyedAt?: string;

  @ApiProperty({
    example: 'unspecified',
    enum: ['timeout', 'manual', 'replaced', 'shutdown', 'unspecified'],
  })
  destroyReason: TcpTrackedSessionDestroyReason;

  @ApiPropertyOptional({
    example: {
      ruleId: 'nat-1',
      bindingId: '123',
      hasSrcNat: true,
      hasDstNat: false,
      allocatedIp: '203.0.113.10',
      allocatedPort: 40000,
    },
  })
  natInfo?: TcpTrackedSessionNatInfo;
}
