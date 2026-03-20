import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';

interface CaCert {
  certPem: string;
  fingerprint: string;
  expiresAt: string;
}

const DEFAULT_PATH = '/var/lib/raptorgate/ca.json';

// Przechowuje certyfikat CA w pamieci i na dysku jako JSON
@Injectable()
export class CaCertStore implements OnModuleInit {
  private readonly logger = new Logger(CaCertStore.name);
  private readonly filePath: string;
  private current: CaCert | null = null;

  constructor() {
    this.filePath = process.env['CA_CERT_PATH'] ?? DEFAULT_PATH;
  }

  // Laduje certyfikat CA z dysku przy starcie
  async onModuleInit() {
    try {
      const raw = await fs.readFile(this.filePath, 'utf-8');
      this.current = JSON.parse(raw) as CaCert;
      this.logger.log(`CA cert loaded from disk fingerprint=${this.current.fingerprint}`);
    } catch {
      this.logger.warn('No CA cert on disk, waiting for fw.ca_ready');
    }
  }

  // Aktualizuje certyfikat CA w pamieci i zapisuje na dysk; pomija jesli fingerprint identyczny
  async upsert(cert: CaCert): Promise<void> {
    if (this.current?.fingerprint === cert.fingerprint) {
      return;
    }
    this.current = cert;
    await fs.mkdir(path.dirname(this.filePath), { recursive: true });
    await fs.writeFile(this.filePath, JSON.stringify(cert, null, 2), 'utf-8');
    this.logger.log(`CA cert updated fingerprint=${cert.fingerprint}`);
  }

  // Zwraca aktualny certyfikat CA lub null
  get(): CaCert | null {
    return this.current;
  }
}
