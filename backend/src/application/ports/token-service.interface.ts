export type TokenPayload = {
	sub: string;
	username: string;
};

export type TokenPair = {
	accessToken: string;
	refreshToken: string;
};

export interface ITokenService {
	generateAccessToken(payload: TokenPayload): Promise<string>;
	generateRefreshToken(): string;
	generateTokenPair(payload: TokenPayload): Promise<TokenPair>;
	verifyAccessToken(
		token: string,
		ignoreExpiration?: boolean,
	): Promise<TokenPayload | null>;
	decodeAccessToken(token: string): TokenPayload | null;
}

export const TOKEN_SERVICE_TOKEN = Symbol("TOKEN_SERVICE_TOKEN");
