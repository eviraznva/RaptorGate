import { CA_CERTIFICATE_READER_TOKEN } from '../ports/ca-certificate-reader.interface.js';
import type { ICaCertificateReader } from '../ports/ca-certificate-reader.interface.js';
import type { CaCertificateData } from '../ports/ca-certificate-reader.interface.js';
import { Inject, Injectable } from '@nestjs/common';

@Injectable()
export class GetCaCertificateUseCase {
  constructor(
    @Inject(CA_CERTIFICATE_READER_TOKEN)
    private readonly caCertificateReader: ICaCertificateReader,
  ) {}

  async execute(): Promise<CaCertificateData> {
    return this.caCertificateReader.read();
  }
}
