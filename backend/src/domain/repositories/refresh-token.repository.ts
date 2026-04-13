export type RefreshTokenRecord = {
	userId: string;
	token: string;
	expiresAt: Date | null;
};

export interface IRefreshTokenRepository {
	set(record: RefreshTokenRecord): Promise<void>;
	getByUserId(userId: string): Promise<RefreshTokenRecord | null>;
	clearByUserId(userId: string): Promise<void>;
}

export const REFRESH_TOKEN_REPOSITORY_TOKEN = Symbol(
	"REFRESH_TOKEN_REPOSITORY_TOKEN",
);
