import { SslBypassEntry } from '../entities/ssl-bypass-entry.entity.js';

export interface ISslBypassRepository {
  save(entry: SslBypassEntry, createdBy?: string): Promise<void>;
  findById(id: string): Promise<SslBypassEntry | null>;
  findAll(): Promise<SslBypassEntry[]>;
  findActive(): Promise<SslBypassEntry[]>;
  overwriteAll(entries: SslBypassEntry[]): Promise<void>;
  delete(id: string): Promise<void>;
}

export const SSL_BYPASS_REPOSITORY_TOKEN = Symbol(
  'SSL_BYPASS_REPOSITORY_TOKEN',
);
