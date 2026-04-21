import { Module } from '@nestjs/common';
import { FirewallEventsController } from './firewall-events.controller.js';
import { FirewallEventsService } from './firewall-events.service.js';

@Module({
  controllers: [FirewallEventsController],
  providers: [FirewallEventsService],
  exports: [FirewallEventsService],
})
export class FirewallEventsModule {}
