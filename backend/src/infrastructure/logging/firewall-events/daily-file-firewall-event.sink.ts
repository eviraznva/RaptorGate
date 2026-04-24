import { Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { FirewallEventSink } from "../../../application/ports/firewall-event-sink.port.js";
import { FirewallEvent } from "../../../domain/firewall-events/firewall-event.js";
import { Env } from "../../../shared/config/env.validation.js";
import { DailyFileLogger } from "../../../shared/logging/daily-file.logger.js";

@Injectable()
export class DailyFileFirewallEventSink implements FirewallEventSink {
  private readonly logger: DailyFileLogger;

  constructor(private readonly configService: ConfigService<Env, true>) {
    this.logger = new DailyFileLogger({
      logDir: this.configService.get("BACKEND_LOG_DIR", { infer: true }),
      context: DailyFileFirewallEventSink.name,
      mirrorToConsole: false,
    });
  }

  write(event: FirewallEvent): Promise<void> {
    this.logger.log({
      event: event.event_type,
      message: event.event_type.replaceAll("_", " "),
      source: event.source,
      decision: event.decision,
      emitted_at: event.timestamp,
      firewall_event: event,
    });

    return Promise.resolve();
  }
}
