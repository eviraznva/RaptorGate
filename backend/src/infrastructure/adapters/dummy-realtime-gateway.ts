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
import { DummyRealtimeStreamService } from "./dummy-realtime-stream.service.js";
import { RealtimeFirewallEventsService } from "./realtime-firewall-events.service.js";
import { mapFirewallEventToRealtimeAlert } from "../realtime/firewall-events/realtime-alert.mapper.js";

@WebSocketGateway({
  namespace: "/realtime",
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
      this.stream.metrics$.subscribe((metric) => {
        this.server.emit("metrics", metric);
      }),
    );

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
    this.logger.log(`Client connected: ${client.id}`);

    for (const event of this.firewallEvents.getRecentEvents()) {
      client.emit("firewall-events", event);
    }
  }

  handleDisconnect(client: Socket) {
    this.logger.log(`Client disconnected: ${client.id}`);
  }

  onModuleDestroy() {
    this.subscriptions.unsubscribe();
  }
}
