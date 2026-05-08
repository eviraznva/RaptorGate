import { Module } from "@nestjs/common";
import { RealtimeAlertsModule } from "./realtime-alerts.module.js";
import { RealtimeMetricsModule } from "./realtime-metrics.module.js";

@Module({
  imports: [RealtimeMetricsModule, RealtimeAlertsModule],
  exports: [RealtimeAlertsModule],
})
export class RealtimeModule {}
