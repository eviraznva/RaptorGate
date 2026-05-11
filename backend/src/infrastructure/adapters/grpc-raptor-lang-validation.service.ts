import {
  Inject,
  Injectable,
  Logger,
  OnModuleInit,
  ServiceUnavailableException,
} from "@nestjs/common";
import type { ClientGrpc } from "@nestjs/microservices";
import { firstValueFrom } from "rxjs";
import { IRaptorLangValidationService } from "../../application/ports/raptor-lang-validation-service.interface.js";
import { RaptorLangValidationException } from "../../domain/exceptions/raptor-lang-validation.exception.js";
import {
  RAPTOR_LANG_VALIDATION_SERVICE_NAME,
  RaptorLangValidationServiceClient,
} from "../grpc/generated/control/validation_service.js";

export const RAPTOR_LANG_VALIDATION_GRPC_CLIENT_TOKEN =
  "RAPTOR_LANG_VALIDATION_GRPC_CLIENT_TOKEN";

@Injectable()
export class GrpcRaptorLangValidationService
  implements IRaptorLangValidationService, OnModuleInit
{
  private readonly logger = new Logger(GrpcRaptorLangValidationService.name);
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
      this.logger.log({
        event: "firewall.raptorlang.validation.started",
        message: "validating RaptorLang content through firewall",
        contentLength: content.length,
      });

      const response = await firstValueFrom(
        this.raptorLangValidationClient.validateRaptorLang({ dsl: content }),
      );

      if (!response.isValid) {
        this.logger.warn({
          event: "firewall.raptorlang.validation.rejected",
          message: response.errorMessage || "RaptorLang content is invalid",
          contentLength: content.length,
        });

        throw new RaptorLangValidationException(
          response.errorMessage || "RaptorLang rule content is invalid.",
        );
      }

      this.logger.log({
        event: "firewall.raptorlang.validation.succeeded",
        message: "RaptorLang content accepted by firewall",
        contentLength: content.length,
      });
    } catch (error) {
      if (error instanceof RaptorLangValidationException) {
        throw error;
      }

      const reason =
        error instanceof Error ? error.message : "Unknown gRPC error";

      this.logger.error(
        {
          event: "firewall.raptorlang.validation.failed",
          message: "RaptorLang validation service call failed",
          contentLength: content.length,
          error: reason,
        },
        error instanceof Error ? error.stack : undefined,
      );

      throw new ServiceUnavailableException(
        `RaptorLang validation service is unavailable. ${reason}`,
      );
    }
  }
}
