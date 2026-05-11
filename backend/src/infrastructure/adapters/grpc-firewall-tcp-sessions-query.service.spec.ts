import { describe, expect, it, jest } from '@jest/globals';
import type {
  ConntrackFlowDto,
  ConntrackMetricsUpdateDto,
} from '../../application/dtos/conntrack-metrics.dto.js';
import type { GrpcFirewallConntrackMetricsStreamService } from './grpc-firewall-conntrack-metrics-stream.service.js';
import { GrpcFirewallTcpSessionsQueryService } from './grpc-firewall-tcp-sessions-query.service.js';

const createService = () => {
  const getConntrackMetricsSnapshot = jest.fn<
    () => Promise<ConntrackMetricsUpdateDto>
  >();
  const mockStream = {
    getConntrackMetricsSnapshot,
  } as unknown as GrpcFirewallConntrackMetricsStreamService;

  const service = new GrpcFirewallTcpSessionsQueryService(mockStream);

  return { service, getConntrackMetricsSnapshot };
};

const makeFlow = (overrides: Partial<ConntrackFlowDto> = {}): ConntrackFlowDto => ({
  id: '1',
  lifecycle: 'active',
  state: 'established',
  lastDirection: 'original',
  original: {
    srcIp: '192.168.1.10',
    srcPort: 52341,
    dstIp: '10.0.0.20',
    dstPort: 443,
    protocol: 'tcp',
  },
  reply: {
    srcIp: '10.0.0.20',
    srcPort: 443,
    dstIp: '192.168.1.10',
    dstPort: 52341,
    protocol: 'tcp',
  },
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
  ...overrides,
});

const update = (flows: ConntrackFlowDto[]): ConntrackMetricsUpdateDto => ({
  timestamp: new Date().toISOString(),
  flows,
});

describe('GrpcFirewallTcpSessionsQueryService', () => {
  it('fetches TCP flows from conntrack metrics snapshot', async () => {
    const { service, getConntrackMetricsSnapshot } = createService();
    getConntrackMetricsSnapshot.mockResolvedValue(update([makeFlow()]));

    const sessions = await service.getTcpSessions();

    expect(getConntrackMetricsSnapshot).toHaveBeenCalledTimes(1);
    expect(sessions).toHaveLength(1);
    expect(sessions[0].getEndpointA().getIpAddress().getValue).toBe('192.168.1.10');
    expect(sessions[0].getEndpointA().getPort().getValue).toBe(52341);
    expect(sessions[0].getEndpointB().getIpAddress().getValue).toBe('10.0.0.20');
    expect(sessions[0].getEndpointB().getPort().getValue).toBe(443);
    expect(sessions[0].getState()).toBe('established');
  });

  it('filters out non-TCP flows', async () => {
    const { service, getConntrackMetricsSnapshot } = createService();
    getConntrackMetricsSnapshot.mockResolvedValue(
      update([
        makeFlow({
          original: {
            srcIp: '10.0.0.1',
            srcPort: 53,
            dstIp: '10.0.0.2',
            dstPort: 53,
            protocol: 'udp',
          },
          reply: {
            srcIp: '10.0.0.2',
            srcPort: 53,
            dstIp: '10.0.0.1',
            dstPort: 53,
            protocol: 'udp',
          },
        }),
      ]),
    );

    const sessions = await service.getTcpSessions();

    expect(sessions).toHaveLength(0);
  });

  it('filters out destroyed flows', async () => {
    const { service, getConntrackMetricsSnapshot } = createService();
    getConntrackMetricsSnapshot.mockResolvedValue(
      update([makeFlow({ lifecycle: 'destroyed', destroyReason: 'timeout' })]),
    );

    const sessions = await service.getTcpSessions();

    expect(sessions).toHaveLength(0);
  });

  it('maps conntrack flow states to TCP session states', async () => {
    const { service, getConntrackMetricsSnapshot } = createService();
    const states = ['new', 'established', 'related', 'invalid', 'unspecified'] as const;
    getConntrackMetricsSnapshot.mockResolvedValue(
      update(states.map((state) => makeFlow({ state }))),
    );

    const sessions = await service.getTcpSessions();

    expect(sessions.map((s) => s.getState())).toEqual([
      'syn_sent',
      'established',
      'established',
      'unknown',
      'unspecified',
    ]);
  });

  it('returns empty array when snapshot has no flows', async () => {
    const { service, getConntrackMetricsSnapshot } = createService();
    getConntrackMetricsSnapshot.mockResolvedValue(update([]));

    const sessions = await service.getTcpSessions();

    expect(sessions).toHaveLength(0);
  });
});
