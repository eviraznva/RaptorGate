import { afterEach, beforeEach, describe, expect, it, jest } from "@jest/globals";
import type { ClientGrpc } from "@nestjs/microservices";
import { EMPTY, of, throwError } from "rxjs";
import type { ConntrackMetricsUpdateDto } from "../../application/dtos/conntrack-metrics.dto.js";
import {
  ConntrackDestroyReason,
  ConntrackDirection,
  ConntrackFlowState,
  ConntrackLifecycle,
  ConntrackProtocol,
  type ConntrackMetricsUpdate,
} from "../grpc/generated/services/metrics_service.js";
import { GrpcFirewallConntrackMetricsStreamService } from "./grpc-firewall-conntrack-metrics-stream.service.js";

const createClient = () => ({
  streamConntrackMetrics: jest.fn(),
});

const timestamp = { seconds: 1_700_000_000, nanos: 123_000_000 };

const update: ConntrackMetricsUpdate = {
  timestamp,
  summary: {
    created: 10,
    confirmed: 9,
    destroyed: 1,
    invalid: 2,
    dropsTableFull: 0,
    lookups: 100,
    hits: 80,
    insertCollisions: 1,
    activeEntries: 1,
    retainedDestroyedEntries: 1,
    historyLimit: 100_000,
  },
  flows: [
    {
      id: 42,
      lifecycle: ConntrackLifecycle.CONNTRACK_LIFECYCLE_ACTIVE,
      state: ConntrackFlowState.CONNTRACK_FLOW_STATE_ESTABLISHED,
      lastDirection: ConntrackDirection.CONNTRACK_DIRECTION_REPLY,
      original: {
        srcIp: "10.0.0.1",
        srcPort: 12345,
        dstIp: "1.1.1.1",
        dstPort: 443,
        protocol: ConntrackProtocol.CONNTRACK_PROTOCOL_TCP,
      },
      reply: {
        srcIp: "1.1.1.1",
        srcPort: 443,
        dstIp: "10.0.0.1",
        dstPort: 12345,
        protocol: ConntrackProtocol.CONNTRACK_PROTOCOL_TCP,
      },
      interfaces: {
        originalIngress: "eth0",
        originalEgress: "tun0",
        replyIngress: "tun0",
        replyEgress: "eth0",
      },
      mark: 7,
      statusBits: 10,
      bytesOriginal: 1000,
      bytesReply: 2000,
      packetsOriginal: 3,
      packetsReply: 4,
      createdAt: timestamp,
      lastSeenAt: timestamp,
      expiresAt: timestamp,
      destroyedAt: undefined,
      destroyReason: ConntrackDestroyReason.CONNTRACK_DESTROY_REASON_UNSPECIFIED,
      natInfo: {
        ruleId: "nat-1",
        bindingId: 123,
        hasSrcNat: true,
        hasDstNat: false,
        allocatedIp: "203.0.113.10",
        allocatedPort: 40000,
        srcManipIp: "203.0.113.10",
        srcManipPort: 40000,
        dstManipIp: undefined,
        dstManipPort: undefined,
      },
    },
  ],
};

describe("GrpcFirewallConntrackMetricsStreamService", () => {
  let client: ReturnType<typeof createClient>;
  let service: GrpcFirewallConntrackMetricsStreamService;

  beforeEach(() => {
    client = createClient();

    const grpcClient = {
      getService: jest.fn().mockReturnValue(client),
    } as unknown as ClientGrpc;

    service = new GrpcFirewallConntrackMetricsStreamService(grpcClient);
  });

  afterEach(() => {
    service.onModuleDestroy();
    jest.useRealTimers();
  });

  it("maps conntrack metric updates", async () => {
    client.streamConntrackMetrics.mockReturnValue(of(update));

    const emitted = new Promise<ConntrackMetricsUpdateDto>((resolve) => {
      service.conntrackMetrics$.subscribe(resolve);
    });

    service.onModuleInit();

    const dto = await emitted;

    expect(client.streamConntrackMetrics).toHaveBeenCalledWith({
      intervalMs: 1000,
      includeDestroyed: true,
    });
    expect(dto.summary?.activeEntries).toBe(1);
    expect(dto.flows[0]).toMatchObject({
      id: "42",
      lifecycle: "active",
      state: "established",
      lastDirection: "reply",
      original: {
        srcIp: "10.0.0.1",
        srcPort: 12345,
        dstIp: "1.1.1.1",
        dstPort: 443,
        protocol: "tcp",
      },
      interfaces: {
        originalIngress: "eth0",
        originalEgress: "tun0",
        replyIngress: "tun0",
        replyEgress: "eth0",
      },
      natInfo: {
        ruleId: "nat-1",
        bindingId: "123",
        hasSrcNat: true,
        hasDstNat: false,
      },
    });
  });

  it("reconnects after stream error", () => {
    jest.useFakeTimers();
    client.streamConntrackMetrics.mockReturnValue(
      throwError(() => new Error("stream broken")),
    );

    service.onModuleInit();
    expect(client.streamConntrackMetrics).toHaveBeenCalledTimes(1);

    jest.advanceTimersByTime(500);

    expect(client.streamConntrackMetrics).toHaveBeenCalledTimes(2);
  });

  it("reconnects after stream completes", () => {
    jest.useFakeTimers();
    client.streamConntrackMetrics.mockReturnValue(EMPTY);

    service.onModuleInit();
    expect(client.streamConntrackMetrics).toHaveBeenCalledTimes(1);

    jest.advanceTimersByTime(500);

    expect(client.streamConntrackMetrics).toHaveBeenCalledTimes(2);
  });

  it("does not reconnect after destroy", () => {
    jest.useFakeTimers();
    client.streamConntrackMetrics.mockReturnValue(
      throwError(() => new Error("stream broken")),
    );

    service.onModuleInit();
    service.onModuleDestroy();
    jest.advanceTimersByTime(500);

    expect(client.streamConntrackMetrics).toHaveBeenCalledTimes(1);
  });
});
