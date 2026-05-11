import {
  BadRequestException,
  Inject,
  Injectable,
  OnModuleInit,
  ServiceUnavailableException,
} from "@nestjs/common";
import type { ClientGrpc } from "@nestjs/microservices";
import { firstValueFrom } from "rxjs";
import type {
  IServerCertificateUploadService,
  UploadServerCertificateInput,
  UploadServerCertificateOutput,
} from "../../application/ports/server-certificate-upload-service.interface.js";
import {
  FIREWALL_SERVER_CERTIFICATE_SERVICE_NAME,
  type FirewallServerCertificateServiceClient,
} from "../grpc/generated/services/server_certificate_service.js";

export const SERVER_CERTIFICATE_UPLOAD_GRPC_CLIENT_TOKEN =
  "SERVER_CERTIFICATE_UPLOAD_GRPC_CLIENT_TOKEN";

@Injectable()
export class GrpcServerCertificateUploadService
  implements IServerCertificateUploadService, OnModuleInit
{
  private client: FirewallServerCertificateServiceClient;

  constructor(
    @Inject(SERVER_CERTIFICATE_UPLOAD_GRPC_CLIENT_TOKEN)
    private readonly grpcClient: ClientGrpc,
  ) {}

  onModuleInit(): void {
    this.client =
      this.grpcClient.getService<FirewallServerCertificateServiceClient>(
        FIREWALL_SERVER_CERTIFICATE_SERVICE_NAME,
      );
  }

  async upload(
    input: UploadServerCertificateInput,
  ): Promise<UploadServerCertificateOutput> {
    let response;
    try {
      response = await firstValueFrom(
        this.client.uploadServerCertificate({
          id: input.id,
          commonName: input.commonName,
          certificatePem: input.certificatePem,
          privateKeyPem: input.privateKeyPem,
          privateKeyRef: input.privateKeyRef,
          bindAddress: input.bindAddress,
          bindPort: input.bindPort,
          inspectionBypass: input.inspectionBypass,
          isActive: input.isActive,
        }),
      );
    } catch (error) {
      const reason =
        error instanceof Error ? error.message : "Unknown gRPC error";
      throw new ServiceUnavailableException(
        `Firewall server certificate service is unavailable. ${reason}`,
      );
    }

    if (!response.accepted) {
      throw new BadRequestException(
        response.error || "Firewall rejected server certificate",
      );
    }

    return { fingerprint: response.fingerprint };
  }
}
