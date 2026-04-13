import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { chmod, mkdir, readFile, unlink, writeFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { Injectable, Inject } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Env } from '../../shared/config/env.validation.js';

const ALGO = 'aes-256-gcm';
const IV_LEN = 12;
const TAG_LEN = 16;

// Szyfrowany store kluczy prywatnych na dysku (AES-256-GCM).
@Injectable()
export class SecretStore {
  private readonly key: Buffer | null;
  private readonly baseDir: string;

  constructor(
    @Inject(ConfigService) configService: ConfigService<Env, true>,
  ) {
    const hex = configService.get('BACKEND_SECRET_ENCRYPTION_KEY', {
      infer: true,
    });
    this.key = hex ? Buffer.from(hex, 'hex') : null;
    this.baseDir = join(process.cwd(), 'data', 'secrets', 'tls-server-keys');
  }

  isConfigured(): boolean {
    return this.key?.length === 32;
  }

  private filePath(ref: string): string {
    return join(this.baseDir, `${ref}.enc`);
  }

  private requireKey(): Buffer {
    if (!this.key || this.key.length !== 32) {
      throw new Error('BACKEND_SECRET_ENCRYPTION_KEY is not configured');
    }
    return this.key;
  }

  async save(ref: string, plaintext: string): Promise<void> {
    const key = this.requireKey();
    const iv = randomBytes(IV_LEN);
    const cipher = createCipheriv(ALGO, key, iv);
    const encrypted = Buffer.concat([
      cipher.update(plaintext, 'utf8'),
      cipher.final(),
    ]);
    const tag = cipher.getAuthTag();
    // format: iv (12) + tag (16) + ciphertext
    const blob = Buffer.concat([iv, tag, encrypted]);
    const path = this.filePath(ref);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, blob);
    await chmod(path, 0o600);
  }

  async load(ref: string): Promise<string> {
    const key = this.requireKey();
    const blob = await readFile(this.filePath(ref));
    const iv = blob.subarray(0, IV_LEN);
    const tag = blob.subarray(IV_LEN, IV_LEN + TAG_LEN);
    const ciphertext = blob.subarray(IV_LEN + TAG_LEN);
    const decipher = createDecipheriv(ALGO, key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]).toString('utf8');
  }

  async exists(ref: string): Promise<boolean> {
    try {
      await readFile(this.filePath(ref));
      return true;
    } catch {
      return false;
    }
  }

  async remove(ref: string): Promise<void> {
    try {
      await unlink(this.filePath(ref));
    } catch {
      // juz nie istnieje
    }
  }

  async missing(refs: string[]): Promise<string[]> {
    const missing: string[] = [];
    for (const ref of refs) {
      if (!(await this.exists(ref))) {
        missing.push(ref);
      }
    }
    return missing;
  }
}
