import { join } from 'node:path';
import { JwtService } from '@nestjs/jwt';
import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { UploadServerCertificateUseCase } from '../application/use-cases/upload-server-certificate.use-case.js';
import { SERVER_CERTIFICATE_UPLOAD_SERVICE_TOKEN } from '../application/ports/server-certificate-upload-service.interface.js';
import { TOKEN_SERVICE_TOKEN } from '../application/ports/token-service.interface.js';
import { FilesystemCaCertificateReader } from '../infrastructure/adapters/filesystem-ca-certificate-reader.js';
import {
  GrpcServerCertificateUploadService,
  SERVER_CERTIFICATE_UPLOAD_GRPC_CLIENT_TOKEN,
} from '../infrastructure/adapters/grpc-server-certificate-upload.service.js';
import { TokenService } from '../infrastructure/adapters/jwt-token.service.js';
import { FileStore } from '../infrastructure/persistence/json/file-store.js';
import { Mutex } from '../infrastructure/persistence/json/file-mutex.js';
import { JsonFirewallCertificateRepository } from '../infrastructure/persistence/repositories/json-firewall-certificate.repository.js';
import { FIREWALL_CERTIFICATE_REPOSITORY_TOKEN } from '../domain/repositories/firewall-certificate.repository.js';
import { CA_CERTIFICATE_READER_TOKEN } from '../application/ports/ca-certificate-reader.interface.js';
import { GetCaCertificateUseCase } from '../application/use-cases/get-ca-certificate.use-case.js';
import { SslController } from '../presentation/controllers/ssl.controller.js';
import { Env } from '../shared/config/env.validation.js';

@Module({
  imports: [
    ClientsModule.registerAsync([
      {
        name: SERVER_CERTIFICATE_UPLOAD_GRPC_CLIENT_TOKEN,
        useFactory: (configService: ConfigService<Env, true>) => {
          const serverCertSocketPath = configService.get(
            'SERVER_CERT_GRPC_SOCKET_PATH',
            { infer: true },
          );

          const grpcUrl = serverCertSocketPath.startsWith('unix://')
            ? serverCertSocketPath
            : `unix://${join(process.cwd(), serverCertSocketPath)}`;

          return {
            transport: Transport.GRPC,
            options: {
              package: 'raptorgate.services',
              protoPath: join(
                process.cwd(),
                '..',
                'proto',
                'services',
                'server_certificate_service.proto',
              ),
              loader: {
                includeDirs: [join(process.cwd(), '..', 'proto')],
              },
              url: grpcUrl,
            },
          };
        },
        inject: [ConfigService],
      },
    ]),
  ],
  controllers: [SslController],
  providers: [
    GetCaCertificateUseCase,
    UploadServerCertificateUseCase,
    GrpcServerCertificateUploadService,
    FileStore,
    Mutex,
    JwtService,
    {
      provide: CA_CERTIFICATE_READER_TOKEN,
      useClass: FilesystemCaCertificateReader,
    },
    {
      provide: FIREWALL_CERTIFICATE_REPOSITORY_TOKEN,
      useClass: JsonFirewallCertificateRepository,
    },
    {
      provide: TOKEN_SERVICE_TOKEN,
      useClass: TokenService,
    },
    {
      provide: SERVER_CERTIFICATE_UPLOAD_SERVICE_TOKEN,
      useExisting: GrpcServerCertificateUploadService,
    },
  ],
})
export class SslModule {}
