export type LoginRequest = {
	username: string;
	password: string;
};

export type LoginResponse = {
	statusCode: number;
	message: string;
	data: {
		id: string;
		username: string;
		createdAt: string;
		accessToken: string;
		recoveryToken: string;
		isFirstLogin: boolean;
		showRecoveryToken: boolean;
		roles: string[];
		authProvider: string;
		authProfileId: string;
	};
};
