import { Controller, Logger } from '@nestjs/common';
import { SkipThrottle } from '@nestjs/throttler';
import { Observable } from 'rxjs';
import { IngestFirewallEventUseCase } from '../../application/use-cases/ingest-firewall-event.use-case.js';
import { IsPublic } from '../../infrastructure/decorators/public.decorator.js';
import { Event } from '../../infrastructure/grpc/generated/events/firewall_events.js';
import {
  BackendEventServiceController,
  BackendEventServiceControllerMethods,
} from '../../infrastructure/grpc/generated/services/event_service.js';
import { mapFirewallEventFromProto } from '../../infrastructure/grpc/mappers/firewall-event-proto.mapper.js';

@Controller()
@IsPublic()
@SkipThrottle()
@BackendEventServiceControllerMethods()
export class FirewallEventsGrpcController
  implements BackendEventServiceController
{
  private readonly logger = new Logger(FirewallEventsGrpcController.name);

  constructor(
    private readonly ingestFirewallEventUseCase: IngestFirewallEventUseCase,
  ) {}

  pushEvents(request: Observable<Event>): Promise<void> {
    this.logger.log('Firewall event stream opened');

    return new Promise<void>((resolve) => {
      const subscription = request.subscribe({
        next: (event) => {
          void this.handleEvent(event);
        },
        error: (err: unknown) => {
          this.logger.warn(
            `Firewall event stream error: ${(err as Error).message}`,
          );
          subscription.unsubscribe();
          resolve();
        },
        complete: () => {
          this.logger.log('Firewall event stream closed');
          resolve();
        },
      });
    });
  }

  private async handleEvent(event: Event): Promise<void> {
    try {
      await this.ingestFirewallEventUseCase.execute(
        mapFirewallEventFromProto(event),
      );
    } catch (err) {
      this.logger.error(
        `Failed to ingest firewall event: ${(err as Error).message}`,
      );
    }
  }
}
