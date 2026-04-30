import {
  WebSocketGateway,
  WebSocketServer,
  OnGatewayInit,
  OnGatewayConnection,
  OnGatewayDisconnect,
} from '@nestjs/websockets';
import { DummyRealtimeStreamService } from './dummy-realtime-stream.service.js';
import { Logger, OnModuleDestroy } from '@nestjs/common';
import { Server, Socket } from 'socket.io';
import { Subscription } from 'rxjs';
import { RealtimeFirewallEventsService } from './realtime-firewall-events.service.js';

@WebSocketGateway({
  namespace: '/realtime',
  cors: {
    origin: true,
    credentials: true,
  },
})
export class RealtimeGateway
  implements
    OnGatewayInit,
    OnGatewayConnection,
    OnGatewayDisconnect,
    OnModuleDestroy
{
  @WebSocketServer()
  server!: Server;

  private readonly logger = new Logger(RealtimeGateway.name);
  private readonly subscriptions = new Subscription();

  constructor(
    private readonly stream: DummyRealtimeStreamService,
    private readonly firewallEvents: RealtimeFirewallEventsService,
  ) {}

  afterInit() {
    this.subscriptions.add(
      this.stream.alerts$.subscribe((alert) => {
        this.server.emit('alerts', alert);
      }),
    );

    this.subscriptions.add(
      this.stream.metrics$.subscribe((metric) => {
        this.server.emit('metrics', metric);
      }),
    );

    this.subscriptions.add(
      this.firewallEvents.firewallEvents$.subscribe((event) => {
        this.server.emit('firewall-events', event);

        if (event.source === 'IPS') {
          this.server.emit('alerts', {
            id: `${event.timestamp}:${event.signature_id ?? event.event_type}`,
            severity: event.decision === 'block' ? 'critical' : 'warning',
            message:
              event.signature_name ??
              `${event.event_type} ${event.src_ip ?? ''} -> ${event.dst_ip ?? ''}`,
            source: 'firewall',
            createdAt: event.timestamp,
          });
        }
      }),
    );
  }

  handleConnection(client: Socket) {
    this.logger.log(`Client connected: ${client.id}`);

    for (const event of this.firewallEvents.getRecentEvents()) {
      client.emit('firewall-events', event);
    }
  }

  handleDisconnect(client: Socket) {
    this.logger.log(`Client disconnected: ${client.id}`);
  }

  onModuleDestroy() {
    this.subscriptions.unsubscribe();
  }
}
