import { describe, expect, it } from '@jest/globals';
import { Subject } from 'rxjs';
import type { ConntrackMetricsUpdateDto } from '../../application/dtos/conntrack-metrics.dto.js';
import type { GrpcFirewallConntrackMetricsStreamService } from './grpc-firewall-conntrack-metrics-stream.service.js';
import { GrpcFirewallTcpSessionsQueryService } from './grpc-firewall-tcp-sessions-query.service.js';

const createService = () => {
  const subject = new Subject<ConntrackMetricsUpdateDto>();
  const mockStream = {
    conntrackMetrics$: subject.asObservable(),
  } as unknown as GrpcFirewallConntrackMetricsStreamService;

  const service = new GrpcFirewallTcpSessionsQueryService(mockStream);
  service.onModuleInit();

  return { service, subject };
};

const makeFlow = (overrides: Record<string, unknown> = {}) => ({
  id: '1',
  lifecycle: 'active' as const,
  state: 'established' as const,
  lastDirection: 'original' as const,
  original: { srcIp: '192.168.1.10', srcPort: 52341, dstIp: '10.0.0.20', dstPort: 443, protocol: 'tcp' as const },
  reply: { srcIp: '10.0.0.20', srcPort: 443, dstIp: '192.168.1.10', dstPort: 52341, protocol: 'tcp' as const },
  interfaces: { originalIngress: '', originalEgress: '', replyIngress: '', replyEgress: '' },
  mark: 0,
  statusBits: 0,
  bytesOriginal: 0,
  bytesReply: 0,
  packetsOriginal: 0,
  packetsReply: 0,
  createdAt: new Date().toISOString(),
  lastSeenAt: new Date().toISOString(),
  expiresAt: new Date().toISOString(),
  destroyReason: 'unspecified' as const,
  ...overrides,
});

const emit = (subject: Subject<ConntrackMetricsUpdateDto>, flows: ReturnType<typeof makeFlow>[]) => {
  subject.next({ timestamp: new Date().toISOString(), flows });
};

describe('GrpcFirewallTcpSessionsQueryService', () => {
  it('returns TCP flows from cached conntrack metrics', async () => {
    const { service, subject } = createService();

    emit(subject, [makeFlow()]);

    const sessions = await service.getTcpSessions();

    expect(sessions).toHaveLength(1);
    expect(sessions[0].getEndpointA().getIpAddress().getValue).toBe('192.168.1.10');
    expect(sessions[0].getEndpointA().getPort().getValue).toBe(52341);
    expect(sessions[0].getEndpointB().getIpAddress().getValue).toBe('10.0.0.20');
    expect(sessions[0].getEndpointB().getPort().getValue).toBe(443);
    expect(sessions[0].getState()).toBe('established');
  });

  it('filters out non-TCP flows', async () => {
    const { service, subject } = createService();

    emit(subject, [
      makeFlow({
        original: { srcIp: '10.0.0.1', srcPort: 53, dstIp: '10.0.0.2', dstPort: 53, protocol: 'udp' },
        reply: { srcIp: '10.0.0.2', srcPort: 53, dstIp: '10.0.0.1', dstPort: 53, protocol: 'udp' },
      }),
    ]);

    const sessions = await service.getTcpSessions();
    expect(sessions).toHaveLength(0);
  });

  it('filters out destroyed flows', async () => {
    const { service, subject } = createService();

    emit(subject, [makeFlow({ lifecycle: 'destroyed', destroyReason: 'timeout' })]);

    const sessions = await service.getTcpSessions();
    expect(sessions).toHaveLength(0);
  });

  it('maps conntrack flow states to TCP session states', async () => {
    const { service, subject } = createService();

    const states = ['new', 'established', 'related', 'invalid', 'unspecified'] as const;
    emit(subject, states.map((state) => makeFlow({ state })));

    const sessions = await service.getTcpSessions();
    expect(sessions.map((s) => s.getState())).toEqual([
      'syn_sent',
      'established',
      'established',
      'unknown',
      'unspecified',
    ]);
  });

  it('returns empty array when no metrics received yet', async () => {
    const { service } = createService();
    const sessions = await service.getTcpSessions();
    expect(sessions).toHaveLength(0);
  });
});
