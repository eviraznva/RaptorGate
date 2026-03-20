import { CaCertStore } from 'src/infrastructure/stores/ca-cert.store';
import { IsPublic } from 'src/infrastructure/decorators/public.decorator';
import { Controller, Get, Res, ServiceUnavailableException } from '@nestjs/common';
import type { Response } from 'express';

// Udostepnia certyfikat CA do pobrania przez klientow
@Controller('pki')
export class PkiController {
  constructor(private readonly caCertStore: CaCertStore) {}

  // Zwraca aktywny certyfikat CA w formacie PEM
  @IsPublic()
  @Get('ca.crt')
  getCaCert(@Res() res: Response): void {
    const ca = this.caCertStore.get();
    if (!ca) {
      throw new ServiceUnavailableException('CA certificate not yet available');
    }
    res.setHeader('Content-Type', 'application/x-pem-file');
    res.setHeader('Content-Disposition', 'attachment; filename="ca.crt"');
    res.send(ca.certPem);
  }
}
