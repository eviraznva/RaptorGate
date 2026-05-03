import { Logger, OnModuleDestroy } from "@nestjs/common";
import {
  OnGatewayConnection,
  OnGatewayDisconnect,
  OnGatewayInit,
  WebSocketGateway,
  WebSocketServer,
} from "@nestjs/websockets";
import { Subscription } from "rxjs";
import { Server, Socket } from "socket.io";
import { mapFirewallEventToRealtimeAlert } from "../realtime/firewall-events/realtime-alert.mapper.js";
import { RealtimeFirewallEventsService } from "./realtime-firewall-events.service.js";

@WebSocketGateway(2001, {
  namespace: "/alerts",
  cors: {
    origin: true,
    credentials: true,
  },
})
export class AlertsGateway
  implements
    OnGatewayInit,
    OnGatewayConnection,
    OnGatewayDisconnect,
    OnModuleDestroy
{
  @WebSocketServer()
  server!: Server;

  private readonly logger = new Logger(AlertsGateway.name);
  private readonly subscriptions = new Subscription();

  constructor(
    private readonly firewallEvents: RealtimeFirewallEventsService,
  ) {}

  afterInit() {
    this.subscriptions.add(
      this.firewallEvents.firewallEvents$.subscribe((event) => {
        this.server.emit("firewall-events", event);

        const alert = mapFirewallEventToRealtimeAlert(event);
        if (alert) {
          this.server.emit("alerts", alert);
        }
      }),
    );
  }

  handleConnection(client: Socket) {
    this.logger.log(`Alerts client connected: ${client.id}`);

    for (const event of this.firewallEvents.getRecentEvents()) {
      client.emit("firewall-events", event);
    }
  }

  handleDisconnect(client: Socket) {
    this.logger.log(`Alerts client disconnected: ${client.id}`);
  }

  onModuleDestroy() {
    this.subscriptions.unsubscribe();
  }
}
