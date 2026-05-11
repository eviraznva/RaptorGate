import { jest } from '@jest/globals';
import { Test, type TestingModule } from '@nestjs/testing';
import { ListIdentitySessionsUseCase } from '../../application/use-cases/list-identity-sessions.use-case.js';
import { RevokeIdentitySessionUseCase } from '../../application/use-cases/revoke-identity-session.use-case.js';
import { IdentitySessionsController } from './identity-sessions.controller.js';

describe('IdentitySessionsController', () => {
  it('returns active identity sessions', async () => {
    const listIdentitySessionsUseCase = {
      execute: jest.fn(async () => ({
        identitySessions: [
          {
            sessionId: 'sess-1',
            sourceIp: '10.0.0.10',
            username: 'user',
            groups: ['users'],
            createdAt: new Date('2026-05-02T10:00:00.000Z'),
            expiresAt: new Date('2026-05-02T10:30:00.000Z'),
          },
        ],
      })),
    };
    const revokeIdentitySessionUseCase = {
      execute: jest.fn(),
    };
    const module: TestingModule = await Test.createTestingModule({
      controllers: [IdentitySessionsController],
      providers: [
        { provide: ListIdentitySessionsUseCase, useValue: listIdentitySessionsUseCase },
        { provide: RevokeIdentitySessionUseCase, useValue: revokeIdentitySessionUseCase },
      ],
    }).compile();
    const controller = module.get(IdentitySessionsController);

    await expect(controller.list()).resolves.toEqual({
      identitySessions: [
        {
          sessionId: 'sess-1',
          sourceIp: '10.0.0.10',
          username: 'user',
          groups: ['users'],
          createdAt: new Date('2026-05-02T10:00:00.000Z'),
          expiresAt: new Date('2026-05-02T10:30:00.000Z'),
        },
      ],
    });
  });

  it('revokes an identity session by session ID and source IP', async () => {
    const listIdentitySessionsUseCase = {
      execute: jest.fn(),
    };
    const revokeIdentitySessionUseCase = {
      execute: jest.fn(async () => ({ removed: true })),
    };
    const module: TestingModule = await Test.createTestingModule({
      controllers: [IdentitySessionsController],
      providers: [
        { provide: ListIdentitySessionsUseCase, useValue: listIdentitySessionsUseCase },
        { provide: RevokeIdentitySessionUseCase, useValue: revokeIdentitySessionUseCase },
      ],
    }).compile();
    const controller = module.get(IdentitySessionsController);

    await expect(controller.revoke({ sessionId: 'sess-1', sourceIp: '10.0.0.10' })).resolves.toEqual({
      removed: true,
    });
    expect(revokeIdentitySessionUseCase.execute).toHaveBeenCalledWith({
      sessionId: 'sess-1',
      sourceIp: '10.0.0.10',
    });
  });
});
