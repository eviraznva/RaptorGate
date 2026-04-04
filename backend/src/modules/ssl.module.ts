import { FilesystemCaCertificateReader } from '../infrastructure/adapters/filesystem-ca-certificate-reader.js';
import { CA_CERTIFICATE_READER_TOKEN } from '../application/ports/ca-certificate-reader.interface.js';
import { GetCaCertificateUseCase } from '../application/use-cases/get-ca-certificate.use-case.js';
import { SslController } from '../presentation/controllers/ssl.controller.js';
import { Module } from '@nestjs/common';

@Module({
  controllers: [SslController],
  providers: [
    GetCaCertificateUseCase,
    {
      provide: CA_CERTIFICATE_READER_TOKEN,
      useClass: FilesystemCaCertificateReader,
    },
  ],
})
export class SslModule {}
