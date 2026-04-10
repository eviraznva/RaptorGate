import { Injectable, Logger } from '@nestjs/common';
import { Event } from '../../infrastructure/grpc/generated/events/firewall_events.js';
import { mapEventToDocument } from './firewall-event.mapper.js';
import { OpenSearchSink } from './opensearch-sink.js';

@Injectable()
export class FirewallEventsService {
  private readonly logger = new Logger(FirewallEventsService.name);

  constructor(private readonly sink: OpenSearchSink) {}

  ingest(event: Event): void {
    const doc = mapEventToDocument(event);
    if (!doc) {
      this.logger.debug('Received event with empty kind, skipping');
      return;
    }
    this.sink.ingest(doc);
  }
}
