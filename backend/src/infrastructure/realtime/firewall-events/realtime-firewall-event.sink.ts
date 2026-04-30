import { Injectable } from '@nestjs/common';
import type { FirewallEventSink } from '../../../application/ports/firewall-event-sink.port.js';
import type { FirewallEvent } from '../../../domain/firewall-events/firewall-event.js';
import { RealtimeFirewallEventsService } from '../../adapters/realtime-firewall-events.service.js';

@Injectable()
export class RealtimeFirewallEventSink implements FirewallEventSink {
  constructor(private readonly realtime: RealtimeFirewallEventsService) {}

  write(event: FirewallEvent): Promise<void> {
    this.realtime.publish(event);
    return Promise.resolve();
  }
}
