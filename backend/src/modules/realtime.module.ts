import { DummyRealtimeStreamService } from 'src/infrastructure/adapters/dummy-realtime-stream.service';
import { RealtimeGateway } from 'src/infrastructure/adapters/dummy-realtime-gateway';
import { Module } from '@nestjs/common';

@Module({
  providers: [DummyRealtimeStreamService, RealtimeGateway],
})
export class RealtimeModule {}
