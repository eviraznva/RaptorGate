import { jest } from '@jest/globals';
import { Test, type TestingModule } from '@nestjs/testing';
import { GetTcpSessionsUseCase } from '../../application/use-cases/get-tcp-sessions.use-case.js';
import {
  TcpSessionEndpoint,
  TcpTrackedSession,
  type TcpTrackedSessionDetails,
} from '../../domain/entities/tcp-tracked-session.entity.js';
import { IpAddress } from '../../domain/value-objects/ip-address.vo.js';
import { Port } from '../../domain/value-objects/port.vo.js';
import { TcpSessionsController } from './tcp-sessions.controller.js';

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
  createdAt: '2026-05-09T10:00:00.000Z',
  lastSeenAt: '2026-05-09T10:00:05.000Z',
  expiresAt: '2026-05-09T10:01:00.000Z',
  destroyReason: 'unspecified',
};

describe('TcpSessionsController', () => {
  it('returns mapped TCP sessions', async () => {
    const tcpSession = TcpTrackedSession.create(
      TcpSessionEndpoint.create(IpAddress.create('192.168.1.10'), Port.create(52341)),
      TcpSessionEndpoint.create(IpAddress.create('10.0.0.20'), Port.create(443)),
      'established',
      details,
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
          ...details,
        },
      ],
    });
    expect(getTcpSessionsUseCase.execute).toHaveBeenCalledWith();
  });
});
