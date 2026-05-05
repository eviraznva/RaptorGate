import { Inject, Injectable, Logger, OnModuleDestroy, OnModuleInit } from "@nestjs/common";
import type { ClientGrpc } from "@nestjs/microservices";
import { Subject, Subscription } from "rxjs";
import type { RealtimeMetricDto } from "../../application/dtos/realtime-metric.dto.js";
import {
  type FirewallMetricsServiceClient,
  FIREWALL_METRICS_SERVICE_NAME,
  type RealtimeMetric,
} from "../grpc/generated/services/metrics_service.js";

export const FIREWALL_METRICS_GRPC_CLIENT_TOKEN = "FIREWALL_METRICS_GRPC_CLIENT_TOKEN";

const INITIAL_BACKOFF_MS = 500;
const MAX_BACKOFF_MS = 30_000;

@Injectable()
export class GrpcFirewallMetricsStreamService
  implements OnModuleInit, OnModuleDestroy
{
  private readonly logger = new Logger(GrpcFirewallMetricsStreamService.name);
  private readonly metricsSubject = new Subject<RealtimeMetricDto>();

  private metricsClient!: FirewallMetricsServiceClient;
  private streamSubscription?: Subscription;
  private backoffMs = INITIAL_BACKOFF_MS;
  private active = false;

  readonly metrics$ = this.metricsSubject.asObservable();

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

    const request = { intervalMs: 1000 };
    const stream = this.metricsClient.streamMetrics(request);

    this.streamSubscription?.unsubscribe();
    this.streamSubscription = stream.subscribe({
      next: (metric: RealtimeMetric) => {
        this.backoffMs = INITIAL_BACKOFF_MS;
        const dto = this.toDto(metric);
        if (!Number.isFinite(dto.value)) {
          this.logger.warn(`Ignoring malformed metric: ${JSON.stringify(metric)}`);
          return;
        }
        this.metricsSubject.next(dto);
      },
      error: (err: unknown) => {
        const message = err instanceof Error ? err.message : String(err);
        this.logger.error(`Metrics stream error: ${message}`);
        this.scheduleReconnect();
      },
      complete: () => {
        this.logger.warn("Metrics stream completed");
        this.scheduleReconnect();
      },
    });
  }

  private scheduleReconnect(): void {
    if (!this.active) return;

    this.logger.log(`Reconnecting in ${this.backoffMs}ms`);
    setTimeout(() => {
      this.backoffMs = Math.min(this.backoffMs * 2, MAX_BACKOFF_MS);
      this.connect();
    }, this.backoffMs);
  }

  private toDto(metric: RealtimeMetric): RealtimeMetricDto {
    return {
      name: metric.name,
      value: Number(metric.value),
      unit: metric.unit,
      timestamp: metric.timestamp
        ? new Date(
            metric.timestamp.seconds * 1000 +
              Math.floor(metric.timestamp.nanos / 1_000_000),
          ).toISOString()
        : new Date().toISOString(),
    };
  }
}
