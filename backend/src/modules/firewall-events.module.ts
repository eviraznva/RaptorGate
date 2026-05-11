import { Module } from '@nestjs/common';
import { FIREWALL_EVENT_SINK_TOKEN } from '../application/ports/firewall-event-sink.port.js';
import { IngestFirewallEventUseCase } from '../application/use-cases/ingest-firewall-event.use-case.js';
import { CompositeFirewallEventSink } from '../infrastructure/firewall-events/composite-firewall-event.sink.js';
import { DailyFileFirewallEventSink } from '../infrastructure/logging/firewall-events/daily-file-firewall-event.sink.js';
import { RealtimeFirewallEventSink } from '../infrastructure/realtime/firewall-events/realtime-firewall-event.sink.js';
import { FirewallEventsGrpcController } from '../presentation/grpc/firewall-events.grpc.controller.js';
import { RealtimeModule } from './realtime.module.js';

@Module({
  imports: [RealtimeModule],
  controllers: [FirewallEventsGrpcController],
  providers: [
    IngestFirewallEventUseCase,
    DailyFileFirewallEventSink,
    RealtimeFirewallEventSink,
    CompositeFirewallEventSink,
    {
      provide: FIREWALL_EVENT_SINK_TOKEN,
      useExisting: CompositeFirewallEventSink,
    },
  ],
  exports: [IngestFirewallEventUseCase],
})
export class FirewallEventsModule {}
