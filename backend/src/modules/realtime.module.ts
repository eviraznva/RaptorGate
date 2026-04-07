import { DummyRealtimeStreamService } from "../infrastructure/adapters/dummy-realtime-stream.service.js";
import { RealtimeGateway } from "../infrastructure/adapters/dummy-realtime-gateway.js";
import { Module } from "@nestjs/common";

@Module({
	providers: [DummyRealtimeStreamService, RealtimeGateway],
})
export class RealtimeModule {}
