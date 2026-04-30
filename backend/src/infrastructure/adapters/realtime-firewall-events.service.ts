import { Injectable } from '@nestjs/common';
import { Subject } from 'rxjs';
import type { RealtimeFirewallEventDto } from '../../application/dtos/realtime-firewall-event.dto.js';

const MAX_RECENT_EVENTS = 100;

@Injectable()
export class RealtimeFirewallEventsService {
  private readonly firewallEventsSubject =
    new Subject<RealtimeFirewallEventDto>();
  private readonly recentEvents: RealtimeFirewallEventDto[] = [];

  readonly firewallEvents$ = this.firewallEventsSubject.asObservable();

  publish(event: RealtimeFirewallEventDto): void {
    this.recentEvents.unshift(event);
    this.recentEvents.length = Math.min(
      this.recentEvents.length,
      MAX_RECENT_EVENTS,
    );
    this.firewallEventsSubject.next(event);
  }

  getRecentEvents(): RealtimeFirewallEventDto[] {
    return [...this.recentEvents];
  }
}
