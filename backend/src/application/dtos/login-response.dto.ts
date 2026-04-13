export class LoginResponseDto {
	id: string;
	username: string;
	createdAt: Date;
	accessToken: string;
	refreshToken: string;
	recoveryToken: string | null;
	isFirstLogin: boolean;
	showRecoveryToken: boolean;
}
