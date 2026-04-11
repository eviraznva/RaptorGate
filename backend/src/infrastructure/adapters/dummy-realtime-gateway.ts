import {
	WebSocketGateway,
	WebSocketServer,
	OnGatewayInit,
	OnGatewayConnection,
	OnGatewayDisconnect,
} from "@nestjs/websockets";
import { DummyRealtimeStreamService } from "./dummy-realtime-stream.service.js";
import { Logger, OnModuleDestroy } from "@nestjs/common";
import { Server, Socket } from "socket.io";
import { Subscription } from "rxjs";

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

	constructor(private readonly stream: DummyRealtimeStreamService) {}

	afterInit() {
		this.subscriptions.add(
			this.stream.alerts$.subscribe((alert) => {
				this.server.emit("alerts", alert);
			}),
		);

		this.subscriptions.add(
			this.stream.metrics$.subscribe((metric) => {
				this.server.emit("metrics", metric);
			}),
		);
	}

	handleConnection(client: Socket) {
		this.logger.log(`Client connected: ${client.id}`);
	}

	handleDisconnect(client: Socket) {
		this.logger.log(`Client disconnected: ${client.id}`);
	}

	onModuleDestroy() {
		this.subscriptions.unsubscribe();
	}
}
