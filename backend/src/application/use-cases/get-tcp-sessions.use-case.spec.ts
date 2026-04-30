import { jest } from '@jest/globals';
import { Test, type TestingModule } from '@nestjs/testing';
import {
  TcpSessionEndpoint,
  TcpTrackedSession,
} from '../../domain/entities/tcp-tracked-session.entity.js';
import { IpAddress } from '../../domain/value-objects/ip-address.vo.js';
import { Port } from '../../domain/value-objects/port.vo.js';
import { FIREWALL_TCP_SESSIONS_QUERY_SERVICE_TOKEN } from '../ports/firewall-tcp-sessions-query-service.interface.js';
import { GetTcpSessionsUseCase } from './get-tcp-sessions.use-case.js';

describe('GetTcpSessionsUseCase', () => {
  it('returns TCP sessions from firewall query service', async () => {
    const tcpSession = TcpTrackedSession.create(
      TcpSessionEndpoint.create(IpAddress.create('192.168.1.10'), Port.create(52341)),
      TcpSessionEndpoint.create(IpAddress.create('10.0.0.20'), Port.create(443)),
      'established',
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
