import { JwtService } from '@nestjs/jwt';
import { Module } from '@nestjs/common';
import { UploadServerCertificateUseCase } from '../application/use-cases/upload-server-certificate.use-case.js';
import { TOKEN_SERVICE_TOKEN } from '../application/ports/token-service.interface.js';
import { FilesystemCaCertificateReader } from '../infrastructure/adapters/filesystem-ca-certificate-reader.js';
import { TokenService } from '../infrastructure/adapters/jwt-token.service.js';
import { SecretStore } from '../infrastructure/persistence/secret-store.js';
import { FileStore } from '../infrastructure/persistence/json/file-store.js';
import { Mutex } from '../infrastructure/persistence/json/file-mutex.js';
import { JsonFirewallCertificateRepository } from '../infrastructure/persistence/repositories/json-firewall-certificate.repository.js';
import { FIREWALL_CERTIFICATE_REPOSITORY_TOKEN } from '../domain/repositories/firewall-certificate.repository.js';
import { CA_CERTIFICATE_READER_TOKEN } from '../application/ports/ca-certificate-reader.interface.js';
import { GetCaCertificateUseCase } from '../application/use-cases/get-ca-certificate.use-case.js';
import { SslController } from '../presentation/controllers/ssl.controller.js';

@Module({
  controllers: [SslController],
  providers: [
    GetCaCertificateUseCase,
    UploadServerCertificateUseCase,
    SecretStore,
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
  ],
})
export class SslModule {}
