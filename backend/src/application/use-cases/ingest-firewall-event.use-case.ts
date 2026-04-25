import { Inject, Injectable, Logger } from "@nestjs/common";
import { FirewallEvent } from "../../domain/firewall-events/firewall-event.js";
import type { FirewallEventSink } from "../ports/firewall-event-sink.port.js";
import { FIREWALL_EVENT_SINK_TOKEN } from "../ports/firewall-event-sink.port.js";

@Injectable()
export class IngestFirewallEventUseCase {
  private readonly logger = new Logger(IngestFirewallEventUseCase.name);

  constructor(
    @Inject(FIREWALL_EVENT_SINK_TOKEN)
    private readonly sink: FirewallEventSink,
  ) {}

  async execute(event: FirewallEvent | null): Promise<void> {
    if (!event) {
      this.logger.debug("Received unsupported firewall event, skipping");
      return;
    }

    await this.sink.write(event);
  }
}
