import { Injectable } from '@nestjs/common';
import type { FirewallEventSink } from '../../application/ports/firewall-event-sink.port.js';
import type { FirewallEvent } from '../../domain/firewall-events/firewall-event.js';
import { DailyFileFirewallEventSink } from '../logging/firewall-events/daily-file-firewall-event.sink.js';
import { RealtimeFirewallEventSink } from '../realtime/firewall-events/realtime-firewall-event.sink.js';

@Injectable()
export class CompositeFirewallEventSink implements FirewallEventSink {
  constructor(
    private readonly dailyFileSink: DailyFileFirewallEventSink,
    private readonly realtimeSink: RealtimeFirewallEventSink,
  ) {}

  async write(event: FirewallEvent): Promise<void> {
    await Promise.all([
      this.dailyFileSink.write(event),
      this.realtimeSink.write(event),
    ]);
  }
}
