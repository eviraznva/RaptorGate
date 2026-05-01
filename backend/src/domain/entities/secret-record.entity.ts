import { SecretIsInvalidException } from '../exceptions/secret-is-invalid.exception.js';
import { SecretRef } from '../value-objects/secret-ref.vo.js';

export class SecretRecord {
  private constructor(
    private readonly ref: string,
    private readonly ciphertext: string,
    private readonly iv: string,
    private readonly authTag: string,
    private readonly createdAt: Date,
    private readonly updatedAt: Date,
    private readonly updatedBy: string,
  ) {}

  public static create(
    ref: string,
    ciphertext: string,
    iv: string,
    authTag: string,
    createdAt: Date,
    updatedAt: Date,
    updatedBy: string,
  ): SecretRecord {
    const validatedRef = SecretRef.create(ref).getValue();

    if (!validatedRef.startsWith('secret://')) {
      throw new SecretIsInvalidException('managed secret storage requires secret:// references');
    }

    requireText(ciphertext, 'secret ciphertext');
    requireText(iv, 'secret iv');
    requireText(authTag, 'secret authTag');
    requireText(updatedBy, 'secret updatedBy');

    return new SecretRecord(
      validatedRef,
      ciphertext,
      iv,
      authTag,
      createdAt,
      updatedAt,
      updatedBy,
    );
  }

  public getRef(): string {
    return this.ref;
  }

  public getCiphertext(): string {
    return this.ciphertext;
  }

  public getIv(): string {
    return this.iv;
  }

  public getAuthTag(): string {
    return this.authTag;
  }

  public getCreatedAt(): Date {
    return this.createdAt;
  }

  public getUpdatedAt(): Date {
    return this.updatedAt;
  }

  public getUpdatedBy(): string {
    return this.updatedBy;
  }
}

function requireText(value: string, field: string): void {
  if (!value.trim()) {
    throw new SecretIsInvalidException(`${field} is required`);
  }
}
