import { Inject, Injectable, Logger } from "@nestjs/common";
import { AccessTokenIsInvalidException } from "../../domain/exceptions/acces-token-is-invalid.exception.js";
import { UserNotFoundException } from "../../domain/exceptions/user-not-found.exception.js";
import {
  ADMIN_AUTH_SESSION_REPOSITORY_TOKEN,
  type IAdminAuthSessionRepository,
} from "../../domain/repositories/admin-auth-session.repository.js";
import type { IUserRepository } from "../../domain/repositories/user.repository.js";
import { USER_REPOSITORY_TOKEN } from "../../domain/repositories/user.repository.js";
import { LogoutUserDto } from "../dtos/logout-user.dto.js";
import type { ITokenService } from "../ports/token-service.interface.js";
import { TOKEN_SERVICE_TOKEN } from "../ports/token-service.interface.js";

@Injectable()
export class LogoutUserUseCase {
  private readonly logger = new Logger(LogoutUserUseCase.name);

  constructor(
    @Inject(USER_REPOSITORY_TOKEN)
    private readonly userRepository: IUserRepository,
    @Inject(TOKEN_SERVICE_TOKEN) private readonly tokenService: ITokenService,
    @Inject(ADMIN_AUTH_SESSION_REPOSITORY_TOKEN)
    private readonly adminAuthSessionRepository: IAdminAuthSessionRepository,
  ) {}

  async execute(dto: LogoutUserDto): Promise<void> {
    const verifiedToken = await this.tokenService.verifyAccessToken(
      dto.accessToken,
    );

    if (!verifiedToken) throw new AccessTokenIsInvalidException();

    const payload = this.tokenService.decodeAccessToken(dto.accessToken);

    if (!payload) throw new AccessTokenIsInvalidException();

    if (payload.principalType === "external_admin") {
      await this.adminAuthSessionRepository.revoke(payload.sub, new Date());
      this.logger.log({
        event: "auth.logout.succeeded",
        message: "external admin logged out",
        sessionId: payload.sub,
        username: payload.username,
      });
      return;
    }

    const user = await this.userRepository.findById(payload.sub);

    if (!user) throw new UserNotFoundException(payload.sub);

    user.setRefreshToken(null);
    user.setRefreshTokenExpiry(null);

    await this.userRepository.setRefreshToken(
      user.getId(),
      user.getRefreshToken(),
      user.getRefreshTokenExpiry(),
    );

    this.logger.log({
      event: "auth.logout.succeeded",
      message: "user logged out",
      userId: user.getId(),
      username: user.getUsername(),
    });
  }
}
