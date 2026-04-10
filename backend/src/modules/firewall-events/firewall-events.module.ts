import { Module } from '@nestjs/common';
import { FirewallEventsController } from './firewall-events.controller.js';
import { FirewallEventsService } from './firewall-events.service.js';
import { OpenSearchSink } from './opensearch-sink.js';

@Module({
  controllers: [FirewallEventsController],
  providers: [FirewallEventsService, OpenSearchSink],
  exports: [FirewallEventsService],
})
export class FirewallEventsModule {}
