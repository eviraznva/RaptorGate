import {
  RaptorGateServiceController,
  RaptorGateServiceControllerMethods,
} from './generated/raptorgate';
import {
  GetConfigRequest,
  ConfigResponse,
} from './generated/config/config_service';
import {
  FirewallEvent,
  HeartbeatEvent,
} from './generated/events/firewall_events';
import { GetActiveConfigUseCase } from 'src/application/use-cases/get-active-config.use-case';
import { BackendEvent, HeartbeatAck } from './generated/events/backend_events';
import { Controller, Inject, Logger } from '@nestjs/common';
import { Observable } from 'rxjs';

@Controller()
@RaptorGateServiceControllerMethods()
export class RaptorGateController implements RaptorGateServiceController {
  private readonly logger = new Logger(RaptorGateController.name);
  constructor(
    @Inject() private readonly getActiveConfigUseCase: GetActiveConfigUseCase,
  ) {}

  async getActiveConfig(request: GetConfigRequest): Promise<ConfigResponse> {
    const activeConfig = await this.getActiveConfigUseCase.execute(
      request.correlationId,
      request.knownVersions,
    );

    // TODO: wczytać aktywną konfigurację z bazy, porównać z known_versions,
    // odesłać pełny bundle lub delta

    return {
      ...activeConfig,
    };
  }

  eventStream(request: Observable<FirewallEvent>): Observable<BackendEvent> {
    return new Observable<BackendEvent>((subscriber) => {
      this.logger.debug('[EventStream] New connection established');
      const sub = request.subscribe({
        next: (envelope) => {
          this.logger.debug(envelope, '[EventStream] Received event');

          switch (envelope.type) {
            case 'fw.heartbeat': {
              const nowMs = Date.now();
              // Zdekoduj payload jako HeartbeatEvent
              const heartbeat = HeartbeatEvent.decode(envelope.payload);
              this.logger.debug(
                heartbeat,
                '[EventStream] Decoded HeartbeatEvent',
              );
              // Zakoduj odpowiedź HeartbeatAck jako payload
              const ackPayload = HeartbeatAck.encode({
                receivedAt: {
                  seconds: Math.floor(nowMs / 1000),
                  nanos: (nowMs % 1000) * 1_000_000,
                },
              }).finish();
              subscriber.next({
                eventId: crypto.randomUUID(),
                type: 'be.heartbeat_ack',
                payload: Buffer.from(ackPayload),
              });
              break;
            }
            default: {
              this.logger.warn(
                `[EventStream] Unknown event type: ${envelope.type}`,
              );
              break;
            }
            // case 'fw.alert': ...
            // case 'fw.policy_activated': ...
          }
        },
        error: (err) => {
          this.logger.error(`[EventStream] Error in event stream: ${err}`);
          return subscriber.error(err);
        },
        complete: () => {
          this.logger.debug('[EventStream] Connection closed by client');
          return subscriber.complete();
        },
      });
      return () => sub.unsubscribe();
    });
  }
}
