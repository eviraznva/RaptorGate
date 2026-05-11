import { randomBytes } from "crypto";
import { IRecoveryTokenService } from "../../application/ports/recovery-token-service.interface.js";

export class RecoveryTokenService implements IRecoveryTokenService {
  constructor() {}

  createRecoveryToken(size: number): string {
    return randomBytes(size).toString("hex");
  }
}
