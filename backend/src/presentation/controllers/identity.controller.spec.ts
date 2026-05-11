import { jest } from '@jest/globals';
import { ForbiddenException } from '@nestjs/common';
import type { Request } from 'express';
import { IdentityController } from './identity.controller.js';

type AsyncExecuteMock = jest.MockedFunction<
  (input?: unknown) => Promise<unknown>
>;

function makeRequest(options: {
  peerIp?: string;
  forwardedFor?: string;
  portalIngress?: string;
}): Request {
  return {
    socket: { remoteAddress: options.peerIp ?? '127.0.0.1' },
    headers: {
      'x-forwarded-for': options.forwardedFor,
      'x-raptorgate-portal-ingress': options.portalIngress,
    },
  } as unknown as Request;
}

describe('IdentityController', () => {
  let authenticateIdentityUseCase: {
    execute: AsyncExecuteMock;
  };
  let logoutIdentityUseCase: {
    execute: AsyncExecuteMock;
  };
  let getIdentitySessionUseCase: {
    execute: AsyncExecuteMock;
  };

  beforeEach(() => {
    authenticateIdentityUseCase = {
      execute: jest.fn<(input?: unknown) => Promise<unknown>>(),
    };
    logoutIdentityUseCase = {
      execute: jest.fn<(input?: unknown) => Promise<unknown>>(),
    };
    getIdentitySessionUseCase = {
      execute: jest.fn<(input?: unknown) => Promise<unknown>>(),
    };
  });

  it('allows login on the client-facing ingress', async () => {
    authenticateIdentityUseCase.execute.mockResolvedValue({
      sessionId: 'sess-1',
      username: 'user',
      sourceIp: '192.168.10.10',
      authenticatedAt: new Date('2026-04-27T15:00:00.000Z'),
      expiresAt: new Date('2026-04-27T15:30:00.000Z'),
    });
    const controller = new IdentityController(
      authenticateIdentityUseCase as never,
      logoutIdentityUseCase as never,
      getIdentitySessionUseCase as never,
    );

    const result = await controller.login(
      { username: 'user', password: 'user123' },
      makeRequest({
        forwardedFor: '192.168.10.10',
        portalIngress: '1',
      }),
    );

    expect(authenticateIdentityUseCase.execute).toHaveBeenCalledWith({
      username: 'user',
      password: 'user123',
      sourceIp: '192.168.10.10',
    });
    expect(result.sourceIp).toBe('192.168.10.10');
  });

  it('blocks login on the management ingress', async () => {
    const controller = new IdentityController(
      authenticateIdentityUseCase as never,
      logoutIdentityUseCase as never,
      getIdentitySessionUseCase as never,
    );

    await expect(
      controller.login(
        { username: 'user', password: 'user123' },
        makeRequest({
          forwardedFor: '192.168.56.1',
          portalIngress: '0',
        }),
      ),
    ).rejects.toBeInstanceOf(ForbiddenException);

    expect(authenticateIdentityUseCase.execute).not.toHaveBeenCalled();
  });

  it('blocks session lookup on the management ingress', async () => {
    const controller = new IdentityController(
      authenticateIdentityUseCase as never,
      logoutIdentityUseCase as never,
      getIdentitySessionUseCase as never,
    );

    await expect(
      controller.session(
        makeRequest({
          forwardedFor: '192.168.56.1',
          portalIngress: '0',
        }),
      ),
    ).rejects.toBeInstanceOf(ForbiddenException);

    expect(getIdentitySessionUseCase.execute).not.toHaveBeenCalled();
  });
});
