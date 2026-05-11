import { Module } from "@nestjs/common";
import { AlertsGateway } from "../infrastructure/adapters/alerts.gateway.js";
import { RealtimeFirewallEventsService } from "../infrastructure/adapters/realtime-firewall-events.service.js";

@Module({
  providers: [RealtimeFirewallEventsService, AlertsGateway],
  exports: [RealtimeFirewallEventsService],
})
export class RealtimeAlertsModule {}
