import { IRecoveryTokenService } from '../../application/ports/recovery-token-service.interface.js';
import { randomBytes } from 'crypto';

export class RecoveryTokenService implements IRecoveryTokenService {
  constructor() {}

  createRecoveryToken(size: number): string {
    return randomBytes(size).toString('hex');
  }
}
