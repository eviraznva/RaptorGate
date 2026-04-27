import { jest } from '@jest/globals';
import { Test, type TestingModule } from '@nestjs/testing';
import { GetTcpSessionsUseCase } from '../../application/use-cases/get-tcp-sessions.use-case.js';
import {
  TcpSessionEndpoint,
  TcpTrackedSession,
} from '../../domain/entities/tcp-tracked-session.entity.js';
import { IpAddress } from '../../domain/value-objects/ip-address.vo.js';
import { Port } from '../../domain/value-objects/port.vo.js';
import { TcpSessionsController } from './tcp-sessions.controller.js';

describe('TcpSessionsController', () => {
  it('returns mapped TCP sessions', async () => {
    const tcpSession = TcpTrackedSession.create(
      TcpSessionEndpoint.create(IpAddress.create('192.168.1.10'), Port.create(52341)),
      TcpSessionEndpoint.create(IpAddress.create('10.0.0.20'), Port.create(443)),
      'established',
    );
    const getTcpSessionsUseCase = {
      execute: jest.fn().mockResolvedValue({ tcpSessions: [tcpSession] }),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [TcpSessionsController],
      providers: [
        {
          provide: GetTcpSessionsUseCase,
          useValue: getTcpSessionsUseCase,
        },
      ],
    }).compile();

    const controller = module.get(TcpSessionsController);

    await expect(controller.getTcpSessions()).resolves.toEqual({
      tcpSessions: [
        {
          endpointA: { ip: '192.168.1.10', port: 52341 },
          endpointB: { ip: '10.0.0.20', port: 443 },
          state: 'established',
        },
      ],
    });
    expect(getTcpSessionsUseCase.execute).toHaveBeenCalledWith();
  });
});
