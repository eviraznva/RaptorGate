import type { ICaCertificateReader } from '../../application/ports/ca-certificate-reader.interface.js';
import type { CaCertificateData } from '../../application/ports/ca-certificate-reader.interface.js';
import { Env } from '../../shared/config/env.validation.js';
import { Injectable, NotFoundException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { readFile } from 'fs/promises';
import { join } from 'path';

@Injectable()
export class FilesystemCaCertificateReader implements ICaCertificateReader {
  constructor(private readonly configService: ConfigService<Env, true>) {}

  async read(): Promise<CaCertificateData> {
    const pkiDir = this.configService.getOrThrow<string>('RAPTORGATE_PKI_DIR');
    const certPath = join(pkiDir, 'ca.crt');
    const metaPath = join(pkiDir, 'ca.meta.json');

    let certPem: string;
    let metaRaw: string;

    try {
      [certPem, metaRaw] = await Promise.all([
        readFile(certPath, 'utf-8'),
        readFile(metaPath, 'utf-8'),
      ]);
    } catch {
      throw new NotFoundException(
        'CA certificate not found — the firewall may not have generated it yet',
      );
    }

    const meta = JSON.parse(metaRaw) as {
      fingerprint: string;
      expires_at_secs: number;
    };

    return {
      certPem,
      fingerprint: meta.fingerprint,
      expiresAt: new Date(meta.expires_at_secs * 1000),
    };
  }
}
