import { Injectable, OnModuleDestroy, OnModuleInit } from "@nestjs/common";
import { Subject } from "rxjs";
import { RealtimeMetricDto } from "../../application/dtos/realtime-metric.dto.js";

@Injectable()
export class DummyRealtimeStreamService
  implements OnModuleInit, OnModuleDestroy
{
  private readonly metricsSubject = new Subject<RealtimeMetricDto>();

  private metricTimer?: NodeJS.Timeout;

  readonly metrics$ = this.metricsSubject.asObservable();

  onModuleInit() {
    this.metricTimer = setInterval(() => this.emitMetric(), 1000);
  }

  onModuleDestroy() {
    if (this.metricTimer) clearInterval(this.metricTimer);
  }

  private emitMetric() {
    const metricPool: Array<Pick<RealtimeMetricDto, "name" | "unit">> = [
      { name: "throughput", unit: "Mbps" },
      { name: "cpu", unit: "%" },
      { name: "memory", unit: "%" },
      { name: "drops", unit: "pps" },
    ];
    const selected = metricPool[Math.floor(Math.random() * metricPool.length)];

    this.metricsSubject.next({
      name: selected.name,
      value: Number((Math.random() * 100).toFixed(2)),
      unit: selected.unit,
      timestamp: new Date().toISOString(),
    });
  }
}
