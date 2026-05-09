import { jest } from '@jest/globals';
import { Test, type TestingModule } from '@nestjs/testing';
import {
  TcpSessionEndpoint,
  TcpTrackedSession,
  type TcpTrackedSessionDetails,
} from '../../domain/entities/tcp-tracked-session.entity.js';
import { IpAddress } from '../../domain/value-objects/ip-address.vo.js';
import { Port } from '../../domain/value-objects/port.vo.js';
import { FIREWALL_TCP_SESSIONS_QUERY_SERVICE_TOKEN } from '../ports/firewall-tcp-sessions-query-service.interface.js';
import { GetTcpSessionsUseCase } from './get-tcp-sessions.use-case.js';

const details: TcpTrackedSessionDetails = {
  id: '1',
  lifecycle: 'active',
  lastDirection: 'original',
  interfaces: {
    originalIngress: '',
    originalEgress: '',
    replyIngress: '',
    replyEgress: '',
  },
  mark: 0,
  statusBits: 0,
  bytesOriginal: 0,
  bytesReply: 0,
  packetsOriginal: 0,
  packetsReply: 0,
  createdAt: new Date().toISOString(),
  lastSeenAt: new Date().toISOString(),
  expiresAt: new Date().toISOString(),
  destroyReason: 'unspecified',
};

describe('GetTcpSessionsUseCase', () => {
  it('returns TCP sessions from firewall query service', async () => {
    const tcpSession = TcpTrackedSession.create(
      TcpSessionEndpoint.create(IpAddress.create('192.168.1.10'), Port.create(52341)),
      TcpSessionEndpoint.create(IpAddress.create('10.0.0.20'), Port.create(443)),
      'established',
      details,
    );
    const firewallTcpSessionsQueryService = {
      getTcpSessions: jest.fn().mockResolvedValue([tcpSession]),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        GetTcpSessionsUseCase,
        {
          provide: FIREWALL_TCP_SESSIONS_QUERY_SERVICE_TOKEN,
          useValue: firewallTcpSessionsQueryService,
        },
      ],
    }).compile();

    const useCase = module.get(GetTcpSessionsUseCase);

    await expect(useCase.execute()).resolves.toEqual({
      tcpSessions: [tcpSession],
    });
    expect(firewallTcpSessionsQueryService.getTcpSessions).toHaveBeenCalledWith();
  });
});
