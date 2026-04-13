import { Inject, Injectable } from '@nestjs/common';
import { join } from 'node:path';
import type { IFirewallCertificateRepository } from '../../../domain/repositories/firewall-certificate.repository.js';
import { FirewallCertificate } from '../../../domain/entities/firewall-certificate.entity.js';
import {
  FirewallCertificatesFileSchema,
  type FirewallCertificatesFile,
} from '../schemas/firewall-certificates.schema.js';
import { FirewallCertificateJsonMapper } from '../mappers/firewall-certificate-json.mapper.js';
import { FileStore } from '../json/file-store.js';
import { Mutex } from '../json/file-mutex.js';

@Injectable()
export class JsonFirewallCertificateRepository
  implements IFirewallCertificateRepository
{
  private readonly filePath = join(
    process.cwd(),
    'data/json-db/firewall_certificates.json',
  );

  constructor(
    @Inject(FileStore) private readonly fileStore: FileStore,
    @Inject(Mutex) private readonly mutex: Mutex,
  ) {}

  private async readPayload(): Promise<FirewallCertificatesFile> {
    const raw = await this.fileStore.readJsonOrDefault<unknown>(this.filePath, {
      items: [],
    });
    return FirewallCertificatesFileSchema.parse(raw);
  }

  async save(cert: FirewallCertificate, createdBy?: string): Promise<void> {
    await this.mutex.runExclusive(async () => {
      const payload = await this.readPayload();
      const idx = payload.items.findIndex((i) => i.id === cert.getId());
      const nextCreatedBy = idx >= 0 ? payload.items[idx].createdBy : createdBy;

      if (!nextCreatedBy) {
        throw new Error('createdBy is required when creating a certificate');
      }

      const next = FirewallCertificateJsonMapper.toRecord(cert, nextCreatedBy);

      if (idx >= 0) {
        payload.items[idx] = next;
      } else {
        payload.items.push(next);
      }

      await this.fileStore.writeJsonAtomic(this.filePath, payload);
    });
  }

  async overwriteAll(certs: FirewallCertificate[]): Promise<void> {
    const items = certs.map((c) =>
      FirewallCertificateJsonMapper.toRecord(c, crypto.randomUUID()),
    );

    await this.mutex.runExclusive(async () => {
      await this.fileStore.writeJsonAtomic(this.filePath, { items });
    });
  }

  async findById(id: string): Promise<FirewallCertificate | null> {
    const payload = await this.readPayload();
    const row = payload.items.find((i) => i.id === id);
    return row ? FirewallCertificateJsonMapper.toDomain(row) : null;
  }

  async findAll(): Promise<FirewallCertificate[]> {
    const payload = await this.readPayload();
    return payload.items.map((i) => FirewallCertificateJsonMapper.toDomain(i));
  }

  async findActive(): Promise<FirewallCertificate[]> {
    const payload = await this.readPayload();
    return payload.items
      .filter((i) => i.isActive)
      .map((i) => FirewallCertificateJsonMapper.toDomain(i));
  }

  async delete(id: string): Promise<void> {
    await this.mutex.runExclusive(async () => {
      const payload = await this.readPayload();
      payload.items = payload.items.filter((i) => i.id !== id);
      await this.fileStore.writeJsonAtomic(this.filePath, payload);
    });
  }
}
