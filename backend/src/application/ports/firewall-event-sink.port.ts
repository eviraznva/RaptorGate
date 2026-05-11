import { FirewallEvent } from '../../domain/firewall-events/firewall-event.js';

export const FIREWALL_EVENT_SINK_TOKEN = Symbol('FIREWALL_EVENT_SINK_TOKEN');

export interface FirewallEventSink {
  write(event: FirewallEvent): Promise<void>;
}
