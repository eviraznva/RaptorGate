export interface IRecoveryTokenService {
	createRecoveryToken(size: number): string;
}

export const RECOVERY_TOKEN_SERVICE_TOKEN = Symbol(
	"RECOVERY_TOKEN_SERVICE_TOKEN",
);
