import { DummyRealtimeStreamService } from '../infrastructure/adapters/dummy-realtime-stream.service.js';
import { RealtimeGateway } from '../infrastructure/adapters/dummy-realtime-gateway.js';
import { Module } from '@nestjs/common';
import { RealtimeFirewallEventsService } from '../infrastructure/adapters/realtime-firewall-events.service.js';

@Module({
  providers: [
    DummyRealtimeStreamService,
    RealtimeFirewallEventsService,
    RealtimeGateway,
  ],
  exports: [RealtimeFirewallEventsService],
})
export class RealtimeModule {}
