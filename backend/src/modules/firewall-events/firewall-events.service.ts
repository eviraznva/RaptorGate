import { appendFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { Injectable, Logger } from "@nestjs/common";
import { Event } from "../../infrastructure/grpc/generated/events/firewall_events.js";
import {
  DEFAULT_BACKEND_LOG_DIR,
  formatLocalDate,
} from "../../shared/logging/daily-file.logger.js";
import { mapEventToDocument } from "./firewall-event.mapper.js";

@Injectable()
export class FirewallEventsService {
  private readonly logger = new Logger(FirewallEventsService.name);
  private readonly logDir =
    process.env.BACKEND_LOG_DIR ?? DEFAULT_BACKEND_LOG_DIR;

  ingest(event: Event): void {
    const doc = mapEventToDocument(event);
    if (!doc) {
      this.logger.debug("Received event with empty kind, skipping");
      return;
    }

    const timestamp = new Date(doc.timestamp);
    const record = {
      ...doc,
      level: "info",
      service: "firewall",
      context: FirewallEventsService.name,
      event: doc.event_type,
      message: doc.event_type.replaceAll("_", " "),
    };

    mkdirSync(this.logDir, { recursive: true });
    appendFileSync(
      join(this.logDir, `${formatLocalDate(timestamp)}.log`),
      `${JSON.stringify(record)}\n`,
      { encoding: "utf8", mode: 0o640 },
    );
  }
}
