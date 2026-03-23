import {
  Inject,
  Injectable,
  OnModuleInit,
  ServiceUnavailableException,
} from '@nestjs/common';
import {
  RAPTOR_LANG_VALIDATION_SERVICE_NAME,
  RaptorLangValidationServiceClient,
} from 'src/infrastructure/grpc/generated/control/validation_service';
import { IRaptorLangValidationService } from 'src/application/ports/raptor-lang-validation-service.interface';
import { RaptorLangValidationException } from 'src/domain/exceptions/raptor-lang-validation.exception';
import type { ClientGrpc } from '@nestjs/microservices';
import { firstValueFrom } from 'rxjs';

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
