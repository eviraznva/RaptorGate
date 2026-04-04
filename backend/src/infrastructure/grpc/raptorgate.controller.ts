import {
  Controller,
  Logger,
  Inject,
  NotImplementedException,
} from '@nestjs/common';
import {
  GetConfigRequest,
  ConfigResponse,
} from './generated/config/config_service';
import { GetActiveConfigUseCase } from '../../application/use-cases/get-active-config.use-case.js';
import { EntityNotFoundException } from '../../domain/exceptions/entity-not-found-exception.js';
import { RpcException } from '@nestjs/microservices';
import { status } from '@grpc/grpc-js';
import { Observable } from 'rxjs';
import {
  RaptorGateServiceControllerMethods,
  RaptorGateServiceController,
} from './generated/config/config_grpc_service';

@Controller()
@RaptorGateServiceControllerMethods()
export class RaptorGateController implements RaptorGateServiceController {
  private readonly logger = new Logger(RaptorGateController.name);
  constructor(
    @Inject() private readonly getActiveConfigUseCase: GetActiveConfigUseCase,
  ) {}

  async getActiveConfig(request: GetConfigRequest): Promise<ConfigResponse> {
    try {
      this.logger.log(
        `[GetActiveConfig] correlationId=${request.correlationId} reason=${request.reason}`,
      );
      const activeConfig = await this.getActiveConfigUseCase.execute();

      this.logger.log(
        `[GetActiveConfig] sending version=${activeConfig.getVersionNumber()}`,
      );
    } catch (error) {
      if (error instanceof EntityNotFoundException) {
        throw new RpcException({
          code: status.NOT_FOUND,
          message: 'No active configuration snapshot found',
        });
      }
    }
    throw new NotImplementedException();
  }

  // eventStream(request: Observable<FirewallEvent>): Observable<BackendEvent> {
  //   return new Observable<BackendEvent>((subscriber) => {
  //     this.logger.log('[EventStream] Firewall connected');
  //     const sub = request.subscribe({
  //       next: (envelope) => {
  //         this.logger.debug(
  //           `[EventStream] Received event type=${envelope.type}`,
  //         );

  //         switch (envelope.type) {
  //           case 'fw.heartbeat': {
  //             const nowMs = Date.now();
  //             // Zdekoduj payload jako HeartbeatEvent
  //             const heartbeat = HeartbeatEvent.decode(envelope.payload);
  //             this.logger.debug(
  //               heartbeat,
  //               '[EventStream] Decoded HeartbeatEvent',
  //             );
  //             // Zakoduj odpowiedź HeartbeatAck jako payload
  //             const ackPayload = HeartbeatAck.encode({
  //               receivedAt: {
  //                 seconds: Math.floor(nowMs / 1000),
  //                 nanos: (nowMs % 1000) * 1_000_000,
  //               },
  //             }).finish();
  //             subscriber.next({
  //               eventId: crypto.randomUUID(),
  //               type: 'be.heartbeat_ack',
  //               payload: Buffer.from(ackPayload),
  //             });
  //             break;
  //           }
  //           default: {
  //             this.logger.warn(
  //               `[EventStream] Unknown event type: ${envelope.type}`,
  //             );
  //             break;
  //           }
  //           // case 'fw.alert': ...
  //           // case 'fw.policy_activated': ...
  //         }
  //       },
  //       error: (err) => {
  //         this.logger.error(`[EventStream] Error in event stream: ${err}`);
  //         return subscriber.error(err);
  //       },
  //       complete: () => {
  //         this.logger.debug('[EventStream] Connection closed by client');
  //         return subscriber.complete();
  //       },
  //     });
  //     return () => sub.unsubscribe();
  //   });
  // }
}
