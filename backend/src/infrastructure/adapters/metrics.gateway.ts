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
import { GrpcFirewallConntrackMetricsStreamService } from "./grpc-firewall-conntrack-metrics-stream.service.js";
import { GrpcFirewallMetricsStreamService } from "./grpc-firewall-metrics-stream.service.js";

@WebSocketGateway(2000, {
  namespace: "/metrics",
  cors: {
    origin: true,
    credentials: true,
  },
})
export class MetricsGateway
  implements
    OnGatewayInit,
    OnGatewayConnection,
    OnGatewayDisconnect,
    OnModuleDestroy
{
  @WebSocketServer()
  server!: Server;

  private readonly logger = new Logger(MetricsGateway.name);
  private readonly subscriptions = new Subscription();

  constructor(
    private readonly metricsStream: GrpcFirewallMetricsStreamService,
    private readonly conntrackMetricsStream: GrpcFirewallConntrackMetricsStreamService,
  ) {}

  afterInit() {
    this.subscriptions.add(
      this.metricsStream.metrics$.subscribe((metric) => {
        this.server.emit("metrics", metric);
      }),
    );
    this.subscriptions.add(
      this.conntrackMetricsStream.conntrackMetrics$.subscribe((metric) => {
        this.server.emit("conntrackMetrics", metric);
      }),
    );
  }

  handleConnection(client: Socket) {
    this.logger.log(`Metrics client connected: ${client.id}`);
  }

  handleDisconnect(client: Socket) {
    this.logger.log(`Metrics client disconnected: ${client.id}`);
  }

  onModuleDestroy() {
    this.subscriptions.unsubscribe();
  }
}
