import { describe, expect, it, jest } from '@jest/globals';
import { ServiceUnavailableException } from '@nestjs/common';
import type { ClientGrpc } from '@nestjs/microservices';
import { of, throwError } from 'rxjs';
import { TcpTrackedSessionState } from '../grpc/generated/services/query_service.js';
import { GrpcFirewallTcpSessionsQueryService } from './grpc-firewall-tcp-sessions-query.service.js';

const createService = (client: { getTcpSessions: jest.Mock }) => {
  const service = new GrpcFirewallTcpSessionsQueryService({
    getService: jest.fn().mockReturnValue(client),
  } as unknown as ClientGrpc);

  service.onModuleInit();

  return service;
};

describe('GrpcFirewallTcpSessionsQueryService', () => {
  it('calls getTcpSessions and maps sessions to domain entities', async () => {
    const client = {
      getTcpSessions: jest.fn(() =>
        of({
          sessions: [
            {
              endpointA: { ip: '192.168.1.10', port: 52341 },
              endpointB: { ip: '10.0.0.20', port: 443 },
              state:
                TcpTrackedSessionState.TCP_TRACKED_SESSION_STATE_ESTABLISHED,
            },
          ],
        }),
      ),
    };
    const service = createService(client);

    const sessions = await service.getTcpSessions();

    expect(client.getTcpSessions).toHaveBeenCalledWith({});
    expect(sessions).toHaveLength(1);
    expect(sessions[0].getEndpointA().getIpAddress().getValue).toBe(
      '192.168.1.10',
    );
    expect(sessions[0].getEndpointA().getPort().getValue).toBe(52341);
    expect(sessions[0].getEndpointB().getIpAddress().getValue).toBe(
      '10.0.0.20',
    );
    expect(sessions[0].getEndpointB().getPort().getValue).toBe(443);
    expect(sessions[0].getState()).toBe('established');
  });

  it('maps every known TCP tracked session state', async () => {
    const client = {
      getTcpSessions: jest.fn(() =>
        of({
          sessions: [
            [
              TcpTrackedSessionState.TCP_TRACKED_SESSION_STATE_UNSPECIFIED,
              'unspecified',
            ],
            [
              TcpTrackedSessionState.TCP_TRACKED_SESSION_STATE_SYN_SENT,
              'syn_sent',
            ],
            [
              TcpTrackedSessionState.TCP_TRACKED_SESSION_STATE_SYN_ACK_RECEIVED,
              'syn_ack_received',
            ],
            [
              TcpTrackedSessionState.TCP_TRACKED_SESSION_STATE_ESTABLISHED,
              'established',
            ],
            [
              TcpTrackedSessionState.TCP_TRACKED_SESSION_STATE_FIN_SENT,
              'fin_sent',
            ],
            [
              TcpTrackedSessionState.TCP_TRACKED_SESSION_STATE_ACK_SENT,
              'ack_sent',
            ],
            [
              TcpTrackedSessionState.TCP_TRACKED_SESSION_STATE_ACK_FIN_SENT,
              'ack_fin_sent',
            ],
            [
              TcpTrackedSessionState.TCP_TRACKED_SESSION_STATE_TIME_WAIT,
              'time_wait',
            ],
            [
              TcpTrackedSessionState.TCP_TRACKED_SESSION_STATE_CLOSED,
              'closed',
            ],
            [TcpTrackedSessionState.UNRECOGNIZED, 'unknown'],
          ].map(([state]) => ({
            endpointA: { ip: '192.168.1.10', port: 52341 },
            endpointB: { ip: '10.0.0.20', port: 443 },
            state,
          })),
        }),
      ),
    };
    const service = createService(client);

    const sessions = await service.getTcpSessions();

    expect(sessions.map((session) => session.getState())).toEqual([
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
    ]);
  });

  it('throws ServiceUnavailableException when grpc call fails', async () => {
    const client = {
      getTcpSessions: jest.fn(() => throwError(() => new Error('offline'))),
    };
    const service = createService(client);

    await expect(service.getTcpSessions()).rejects.toThrow(
      ServiceUnavailableException,
    );
  });

  it('throws ServiceUnavailableException when grpc session has missing endpoint', async () => {
    const client = {
      getTcpSessions: jest.fn(() =>
        of({
          sessions: [
            {
              endpointA: { ip: '192.168.1.10', port: 52341 },
              state:
                TcpTrackedSessionState.TCP_TRACKED_SESSION_STATE_ESTABLISHED,
            },
          ],
        }),
      ),
    };
    const service = createService(client);

    await expect(service.getTcpSessions()).rejects.toThrow(
      ServiceUnavailableException,
    );
  });
});
