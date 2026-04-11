import {
  Inject,
  Injectable,
  OnModuleInit,
  ServiceUnavailableException,
} from '@nestjs/common';
import type { ClientGrpc } from '@nestjs/microservices';
import { firstValueFrom } from 'rxjs';
import { IRaptorLangValidationService } from '../../application/ports/raptor-lang-validation-service.interface.js';
import { RaptorLangValidationException } from '../../domain/exceptions/raptor-lang-validation.exception.js';
import {
  RAPTOR_LANG_VALIDATION_SERVICE_NAME,
  RaptorLangValidationServiceClient,
} from '../grpc/generated/control/validation_service.js';

export const RAPTOR_LANG_VALIDATION_GRPC_CLIENT_TOKEN =
  'RAPTOR_LANG_VALIDATION_GRPC_CLIENT_TOKEN';

@Injectable()
export class GrpcRaptorLangValidationService
  implements IRaptorLangValidationService, OnModuleInit
{
  private raptorLangValidationClient: RaptorLangValidationServiceClient;

  constructor(
    @Inject(RAPTOR_LANG_VALIDATION_GRPC_CLIENT_TOKEN)
    private readonly grpcClient: ClientGrpc,
  ) {}

  onModuleInit(): void {
    this.raptorLangValidationClient =
      this.grpcClient.getService<RaptorLangValidationServiceClient>(
        RAPTOR_LANG_VALIDATION_SERVICE_NAME,
      );
  }

  async validateRaptorLang(content: string): Promise<void> {
    try {
      const response = await firstValueFrom(
        this.raptorLangValidationClient.validateRaptorLang({ dsl: content }),
      );

      if (!response.isValid) {
        throw new RaptorLangValidationException(
          response.errorMessage || 'RaptorLang rule content is invalid.',
        );
      }
    } catch (error) {
      if (error instanceof RaptorLangValidationException) {
        throw error;
      }

      const reason =
        error instanceof Error ? error.message : 'Unknown gRPC error';

      throw new ServiceUnavailableException(
        `RaptorLang validation service is unavailable. ${reason}`,
      );
    }
  }
}
