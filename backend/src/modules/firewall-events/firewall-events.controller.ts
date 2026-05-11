import { Controller, Logger } from '@nestjs/common';
import { SkipThrottle } from '@nestjs/throttler';
import { Observable } from 'rxjs';
import { Event } from '../../infrastructure/grpc/generated/events/firewall_events.js';
import { IsPublic } from '../../infrastructure/decorators/public.decorator.js';
import {
  BackendEventServiceController,
  BackendEventServiceControllerMethods,
} from '../../infrastructure/grpc/generated/services/event_service.js';
import { FirewallEventsService } from './firewall-events.service.js';

@Controller()
@IsPublic()
@SkipThrottle()
@BackendEventServiceControllerMethods()
export class FirewallEventsController implements BackendEventServiceController {
  private readonly logger = new Logger(FirewallEventsController.name);

  constructor(private readonly service: FirewallEventsService) {}

  pushEvents(request: Observable<Event>): Promise<void> {
    this.logger.log('Firewall event stream opened');
    return new Promise<void>((resolve) => {
      const sub = request.subscribe({
        next: (event) => {
          try {
            this.service.ingest(event);
          } catch (err) {
            this.logger.error(
              `Failed to ingest firewall event: ${(err as Error).message}`,
            );
          }
        },
        error: (err: unknown) => {
          this.logger.warn(
            `Firewall event stream error: ${(err as Error).message}`,
          );
          sub.unsubscribe();
          resolve();
        },
        complete: () => {
          this.logger.log('Firewall event stream closed');
          resolve();
        },
      });
    });
  }
}
