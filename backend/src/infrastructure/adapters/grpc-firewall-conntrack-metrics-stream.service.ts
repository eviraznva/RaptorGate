import { Inject, Injectable, Logger, OnModuleDestroy, OnModuleInit } from "@nestjs/common";
import type { ClientGrpc } from "@nestjs/microservices";
import { Subject, Subscription } from "rxjs";
import type {
  ConntrackDestroyReasonDto,
  ConntrackDirectionDto,
  ConntrackFlowDto,
  ConntrackFlowStateDto,
  ConntrackFlowTupleDto,
  ConntrackLifecycleDto,
  ConntrackMetricsUpdateDto,
  ConntrackNatInfoDto,
  ConntrackProtocolDto,
} from "../../application/dtos/conntrack-metrics.dto.js";
import {
  ConntrackDestroyReason,
  ConntrackDirection,
  type ConntrackFlow,
  ConntrackFlowState,
  type ConntrackFlowTuple,
  ConntrackLifecycle,
  type ConntrackMetricsUpdate,
  type ConntrackNatInfo,
  ConntrackProtocol,
  type FirewallMetricsServiceClient,
  FIREWALL_METRICS_SERVICE_NAME,
} from "../grpc/generated/services/metrics_service.js";
import { FIREWALL_METRICS_GRPC_CLIENT_TOKEN } from "./grpc-firewall-metrics-stream.service.js";

const INITIAL_BACKOFF_MS = 500;
const MAX_BACKOFF_MS = 30_000;

@Injectable()
export class GrpcFirewallConntrackMetricsStreamService
  implements OnModuleInit, OnModuleDestroy
{
  private readonly logger = new Logger(GrpcFirewallConntrackMetricsStreamService.name);
  private readonly metricsSubject = new Subject<ConntrackMetricsUpdateDto>();

  private metricsClient!: FirewallMetricsServiceClient;
  private streamSubscription?: Subscription;
  private backoffMs = INITIAL_BACKOFF_MS;
  private active = false;

  readonly conntrackMetrics$ = this.metricsSubject.asObservable();

  constructor(
    @Inject(FIREWALL_METRICS_GRPC_CLIENT_TOKEN)
    private readonly grpcClient: ClientGrpc,
  ) {}

  onModuleInit(): void {
    this.metricsClient = this.grpcClient.getService<FirewallMetricsServiceClient>(
      FIREWALL_METRICS_SERVICE_NAME,
    );
    this.active = true;
    this.connect();
  }

  onModuleDestroy(): void {
    this.active = false;
    this.streamSubscription?.unsubscribe();
  }

  private connect(): void {
    if (!this.active) return;

    const request = { intervalMs: 1000, includeDestroyed: true };
    const stream = this.metricsClient.streamConntrackMetrics(request);

    this.streamSubscription?.unsubscribe();
    this.streamSubscription = stream.subscribe({
      next: (update: ConntrackMetricsUpdate) => {
        this.backoffMs = INITIAL_BACKOFF_MS;
        this.metricsSubject.next(this.toDto(update));
      },
      error: (err: unknown) => {
        const message = err instanceof Error ? err.message : String(err);
        this.logger.error(`Conntrack metrics stream error: ${message}`);
        this.scheduleReconnect();
      },
      complete: () => {
        this.logger.warn("Conntrack metrics stream completed");
        this.scheduleReconnect();
      },
    });
  }

  private scheduleReconnect(): void {
    if (!this.active) return;

    this.logger.log(`Reconnecting conntrack metrics in ${this.backoffMs}ms`);
    setTimeout(() => {
      this.backoffMs = Math.min(this.backoffMs * 2, MAX_BACKOFF_MS);
      this.connect();
    }, this.backoffMs);
  }

  private toDto(update: ConntrackMetricsUpdate): ConntrackMetricsUpdateDto {
    return {
      timestamp: this.toTimestamp(update.timestamp),
      summary: update.summary,
      flows: (update.flows ?? []).map((flow) => this.toFlowDto(flow)),
    };
  }

  private toFlowDto(flow: ConntrackFlow): ConntrackFlowDto {
    return {
      id: String(flow.id),
      lifecycle: this.toLifecycleDto(flow.lifecycle),
      state: this.toStateDto(flow.state),
      lastDirection: this.toDirectionDto(flow.lastDirection),
      original: this.toTupleDto(flow.original),
      reply: this.toTupleDto(flow.reply),
      interfaces: {
        originalIngress: flow.interfaces?.originalIngress ?? "",
        originalEgress: flow.interfaces?.originalEgress ?? "",
        replyIngress: flow.interfaces?.replyIngress ?? "",
        replyEgress: flow.interfaces?.replyEgress ?? "",
      },
      mark: flow.mark,
      statusBits: flow.statusBits,
      bytesOriginal: flow.bytesOriginal,
      bytesReply: flow.bytesReply,
      packetsOriginal: flow.packetsOriginal,
      packetsReply: flow.packetsReply,
      createdAt: this.toTimestamp(flow.createdAt),
      lastSeenAt: this.toTimestamp(flow.lastSeenAt),
      expiresAt: this.toTimestamp(flow.expiresAt),
      destroyedAt: flow.destroyedAt ? this.toTimestamp(flow.destroyedAt) : undefined,
      destroyReason: this.toDestroyReasonDto(flow.destroyReason),
      natInfo: flow.natInfo ? this.toNatInfoDto(flow.natInfo) : undefined,
    };
  }

  private toTupleDto(tuple?: ConntrackFlowTuple): ConntrackFlowTupleDto {
    return {
      srcIp: tuple?.srcIp ?? "",
      srcPort: tuple?.srcPort ?? 0,
      dstIp: tuple?.dstIp ?? "",
      dstPort: tuple?.dstPort ?? 0,
      protocol: this.toProtocolDto(
        tuple?.protocol ?? ConntrackProtocol.CONNTRACK_PROTOCOL_UNSPECIFIED,
      ),
    };
  }

  private toNatInfoDto(natInfo: ConntrackNatInfo): ConntrackNatInfoDto {
    return {
      ruleId: natInfo.ruleId,
      bindingId: String(natInfo.bindingId),
      hasSrcNat: natInfo.hasSrcNat,
      hasDstNat: natInfo.hasDstNat,
      allocatedIp: natInfo.allocatedIp,
      allocatedPort: natInfo.allocatedPort,
      srcManipIp: natInfo.srcManipIp,
      srcManipPort: natInfo.srcManipPort,
      dstManipIp: natInfo.dstManipIp,
      dstManipPort: natInfo.dstManipPort,
    };
  }

  private toTimestamp(timestamp: ConntrackMetricsUpdate["timestamp"]): string {
    return timestamp
      ? new Date(
          timestamp.seconds * 1000 + Math.floor(timestamp.nanos / 1_000_000),
        ).toISOString()
      : new Date().toISOString();
  }

  private toLifecycleDto(value: ConntrackLifecycle): ConntrackLifecycleDto {
    switch (value) {
      case ConntrackLifecycle.CONNTRACK_LIFECYCLE_ACTIVE:
        return "active";
      case ConntrackLifecycle.CONNTRACK_LIFECYCLE_DESTROYED:
        return "destroyed";
      default:
        return "unspecified";
    }
  }

  private toStateDto(value: ConntrackFlowState): ConntrackFlowStateDto {
    switch (value) {
      case ConntrackFlowState.CONNTRACK_FLOW_STATE_NEW:
        return "new";
      case ConntrackFlowState.CONNTRACK_FLOW_STATE_ESTABLISHED:
        return "established";
      case ConntrackFlowState.CONNTRACK_FLOW_STATE_RELATED:
        return "related";
      case ConntrackFlowState.CONNTRACK_FLOW_STATE_INVALID:
        return "invalid";
      default:
        return "unspecified";
    }
  }

  private toDirectionDto(value: ConntrackDirection): ConntrackDirectionDto {
    switch (value) {
      case ConntrackDirection.CONNTRACK_DIRECTION_ORIGINAL:
        return "original";
      case ConntrackDirection.CONNTRACK_DIRECTION_REPLY:
        return "reply";
      default:
        return "unspecified";
    }
  }

  private toProtocolDto(value: ConntrackProtocol): ConntrackProtocolDto {
    switch (value) {
      case ConntrackProtocol.CONNTRACK_PROTOCOL_TCP:
        return "tcp";
      case ConntrackProtocol.CONNTRACK_PROTOCOL_UDP:
        return "udp";
      case ConntrackProtocol.CONNTRACK_PROTOCOL_ICMP:
        return "icmp";
      case ConntrackProtocol.CONNTRACK_PROTOCOL_ICMPV6:
        return "icmpv6";
      default:
        return "unknown";
    }
  }

  private toDestroyReasonDto(value: ConntrackDestroyReason): ConntrackDestroyReasonDto {
    switch (value) {
      case ConntrackDestroyReason.CONNTRACK_DESTROY_REASON_TIMEOUT:
        return "timeout";
      case ConntrackDestroyReason.CONNTRACK_DESTROY_REASON_MANUAL:
        return "manual";
      case ConntrackDestroyReason.CONNTRACK_DESTROY_REASON_REPLACED:
        return "replaced";
      case ConntrackDestroyReason.CONNTRACK_DESTROY_REASON_SHUTDOWN:
        return "shutdown";
      default:
        return "unspecified";
    }
  }
}
