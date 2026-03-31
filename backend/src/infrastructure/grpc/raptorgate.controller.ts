import {
  BackendEventServiceController,
  BackendEventServiceControllerMethods,
} from './generated/services/event_service.js';
import { Controller, Logger } from '@nestjs/common';
import { Event } from './generated/events/firewall_events.js';
import { Observable } from 'rxjs';

@Controller()
@BackendEventServiceControllerMethods()
export class RaptorGateController implements BackendEventServiceController {
  private readonly logger = new Logger(RaptorGateController.name);

  async pushEvents(request: Observable<Event>): Promise<void> {
    this.logger.log('[PushEvents] Firewall connected');

    return new Promise<void>((resolve, reject) => {
      const sub = request.subscribe({
        next: (event) => {
          const eventKind = event.kind?.item?.$case ?? 'unknown';

          this.logger.debug(`[PushEvents] Received event kind=${eventKind}`);
        },
        error: (error) => {
          const reason = error instanceof Error ? error.message : String(error);

          this.logger.error(`[PushEvents] Stream error: ${reason}`);
          sub.unsubscribe();
          reject(error);
        },
        complete: () => {
          this.logger.debug('[PushEvents] Stream closed by client');
          sub.unsubscribe();
          resolve();
        },
      });
    });
  }
}
