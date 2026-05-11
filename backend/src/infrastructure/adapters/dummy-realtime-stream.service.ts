import { RealtimeMetricDto } from '../../presentation/dtos/realtime-metric.dto.js';
import { RealtimeAlertDto } from '../../presentation/dtos/realtime-alert.dto.js';
import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { Subject } from 'rxjs';

@Injectable()
export class DummyRealtimeStreamService
  implements OnModuleInit, OnModuleDestroy
{
  private readonly alertsSubject = new Subject<RealtimeAlertDto>();
  private readonly metricsSubject = new Subject<RealtimeMetricDto>();

  private alertTimer?: NodeJS.Timeout;
  private metricTimer?: NodeJS.Timeout;
  private alertSeq = 0;

  readonly alerts$ = this.alertsSubject.asObservable();
  readonly metrics$ = this.metricsSubject.asObservable();

  onModuleInit() {
    this.alertTimer = setInterval(() => this.emitAlert(), 5000);
    this.metricTimer = setInterval(() => this.emitMetric(), 1000);
  }

  onModuleDestroy() {
    if (this.alertTimer) clearInterval(this.alertTimer);
    if (this.metricTimer) clearInterval(this.metricTimer);
  }

  private emitAlert() {
    const severities: RealtimeAlertDto['severity'][] = [
      'info',
      'warning',
      'critical',
    ];
    const severity = severities[this.alertSeq % severities.length];

    this.alertsSubject.next({
      id: randomUUID(),
      severity,
      message:
        severity === 'critical'
          ? 'Drop rate spike detected'
          : severity === 'warning'
            ? 'Elevated latency observed'
            : 'Firewall heartbeat ok',
      source: 'firewall',
      createdAt: new Date().toISOString(),
    });

    this.alertSeq += 1;
  }

  private emitMetric() {
    const metricPool: Array<Pick<RealtimeMetricDto, 'name' | 'unit'>> = [
      { name: 'throughput', unit: 'Mbps' },
      { name: 'cpu', unit: '%' },
      { name: 'memory', unit: '%' },
      { name: 'drops', unit: 'pps' },
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
