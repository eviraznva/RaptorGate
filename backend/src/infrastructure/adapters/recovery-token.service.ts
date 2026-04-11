import { IRecoveryTokenService } from "src/application/ports/recovery-token-service.interface";
import { randomBytes } from "crypto";

export class RecoveryTokenService implements IRecoveryTokenService {
	constructor() {}

	createRecoveryToken(size: number): string {
		return randomBytes(size).toString("hex");
	}
}
