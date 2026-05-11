import { Inject, Injectable, Logger } from "@nestjs/common";
import type { AdminAuthSession } from "../../domain/entities/admin-auth-session.entity.js";
import { RefreshTokenIsInvalidException } from "../../domain/exceptions/refresh-token-is-invalid.exception.js";
import { UserNotFoundException } from "../../domain/exceptions/user-not-found.exception.js";
import {
  ADMIN_AUTH_SESSION_REPOSITORY_TOKEN,
  type IAdminAuthSessionRepository,
} from "../../domain/repositories/admin-auth-session.repository.js";
import type { IUserRepository } from "../../domain/repositories/user.repository.js";
import { USER_REPOSITORY_TOKEN } from "../../domain/repositories/user.repository.js";
import { RefreshTokenDto } from "../dtos/refresh-token.dto.js";
import { RefreshTokenResponseDto } from "../dtos/refresh-token-response.dto.js";
import {
  type IPasswordHasher,
  PASSWORD_HASHER_TOKEN,
} from "../ports/passowrd-hasher.interface.js";
import type {
  ITokenService,
  TokenPayload,
} from "../ports/token-service.interface.js";
import { TOKEN_SERVICE_TOKEN } from "../ports/token-service.interface.js";

@Injectable()
export class RefreshTokenUseCase {
  private readonly logger = new Logger(RefreshTokenUseCase.name);

  constructor(
    @Inject(TOKEN_SERVICE_TOKEN) private readonly tokenService: ITokenService,
    @Inject(USER_REPOSITORY_TOKEN)
    private readonly userRepository: IUserRepository,
    @Inject(ADMIN_AUTH_SESSION_REPOSITORY_TOKEN)
    private readonly adminAuthSessionRepository: IAdminAuthSessionRepository,
    @Inject(PASSWORD_HASHER_TOKEN)
    private readonly passwordHasher: IPasswordHasher,
  ) {}

  async execute(dto: RefreshTokenDto): Promise<RefreshTokenResponseDto> {
    const verifiedPayload = await this.tokenService.verifyAccessToken(
      dto.accessToken,
      true,
    );

    if (!verifiedPayload) throw new RefreshTokenIsInvalidException();

    const payload = this.tokenService.decodeAccessToken(dto.accessToken);
    if (!payload) throw new RefreshTokenIsInvalidException();

    if (payload.principalType === "external_admin") {
      return this.refreshExternalAdmin(payload, dto.refreshToken);
    }

    const user = await this.userRepository.findById(payload.sub);
    if (!user) throw new UserNotFoundException(payload.sub);

    if (user.getRefreshToken() !== dto.refreshToken) {
      this.logger.warn({
        event: "auth.refresh.failed",
        message: "refresh token mismatch",
        userId: user.getId(),
        username: user.getUsername(),
      });
      throw new RefreshTokenIsInvalidException();
    }

    const now = new Date();
    const expiry = user.getRefreshTokenExpiry()!;

    const timeUntilExpiry = expiry.getTime() - now.getTime();
    const timeSinceExpiry = now.getTime() - expiry.getTime();

    const GRACE_PERIOD_MS = 60 * 60 * 1000;
    const THRESHOLD_MS = 45 * 60 * 1000;

    if (timeSinceExpiry > GRACE_PERIOD_MS) {
      user.setRefreshToken(null);

      await this.userRepository.setRefreshToken(user.getId(), null, null);
      this.logger.warn({
        event: "auth.refresh.failed",
        message: "refresh token expired outside grace period",
        userId: user.getId(),
        username: user.getUsername(),
      });
      throw new RefreshTokenIsInvalidException();
    }

    if (timeUntilExpiry < THRESHOLD_MS) {
      const newExpiry = new Date(now.getTime() + 60 * 60 * 1000);

      const newTokenPair = await this.tokenService.generateTokenPair({
        sub: user.getId(),
        username: user.getUsername(),
      });

      user.setRefreshTokenExpiry(newExpiry);
      user.setRefreshToken(newTokenPair.refreshToken);

      await this.userRepository.setRefreshToken(
        user.getId(),
        newTokenPair.refreshToken,
        user.getRefreshTokenExpiry(),
      );

      this.logger.log({
        event: "auth.refresh.rotated",
        message: "refresh token rotated",
        userId: user.getId(),
        username: user.getUsername(),
      });

      return {
        accessToken: newTokenPair.accessToken,
        refreshToken: newTokenPair.refreshToken,
      };
    } else {
      const accessToken = await this.tokenService.generateAccessToken({
        sub: user.getId(),
        username: user.getUsername(),
      });

      this.logger.log({
        event: "auth.refresh.succeeded",
        message: "access token refreshed",
        userId: user.getId(),
        username: user.getUsername(),
      });

      return {
        accessToken,
      };
    }
  }

  private async refreshExternalAdmin(
    payload: TokenPayload,
    refreshToken: string,
  ): Promise<RefreshTokenResponseDto> {
    const session = await this.adminAuthSessionRepository.findById(payload.sub);
    if (!session || session.isRevoked()) {
      throw new RefreshTokenIsInvalidException();
    }

    if (
      !(await this.passwordHasher.compare(
        refreshToken,
        session.getRefreshTokenHash(),
      ))
    ) {
      this.logger.warn({
        event: "auth.refresh.failed",
        message: "external admin refresh token mismatch",
        sessionId: session.getId(),
        username: session.getUsername(),
      });
      throw new RefreshTokenIsInvalidException();
    }

    const now = new Date();
    const expiry = session.getRefreshTokenExpiry();
    const timeSinceExpiry = now.getTime() - expiry.getTime();

    const GRACE_PERIOD_MS = 60 * 60 * 1000;

    if (timeSinceExpiry > GRACE_PERIOD_MS) {
      await this.adminAuthSessionRepository.revoke(session.getId(), now);
      throw new RefreshTokenIsInvalidException();
    }

    return this.rotateExternalAdminRefreshToken(session, now);
  }

  private async rotateExternalAdminRefreshToken(
    session: AdminAuthSession,
    now: Date,
  ): Promise<RefreshTokenResponseDto> {
    const newExpiry = new Date(now.getTime() + 60 * 60 * 1000);
    const tokenPair = await this.tokenService.generateTokenPair(
      externalAdminPayload(session),
    );
    const refreshTokenHash = await this.passwordHasher.hash(
      tokenPair.refreshToken,
    );

    session.rotateRefreshToken(refreshTokenHash, newExpiry);
    session.touch(now);
    await this.adminAuthSessionRepository.save(session);

    return {
      accessToken: tokenPair.accessToken,
      refreshToken: tokenPair.refreshToken,
    };
  }
}

function externalAdminPayload(session: AdminAuthSession): TokenPayload {
  return {
    sub: session.getId(),
    username: session.getUsername(),
    principalType: "external_admin",
    roles: session.getRoles(),
    authProvider: session.getProvider(),
    authProfileId: session.getAuthProfileId(),
    externalId: session.getExternalId(),
  };
}
