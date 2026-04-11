import { Inject, Injectable } from "@nestjs/common";
import { RefreshTokenIsInvalidException } from "../../domain/exceptions/refresh-token-is-invalid.exception.js";
import { UserNotFoundException } from "../../domain/exceptions/user-not-found.exception.js";
import type { IUserRepository } from "../../domain/repositories/user.repository.js";
import { USER_REPOSITORY_TOKEN } from "../../domain/repositories/user.repository.js";
import { RefreshTokenDto } from "../dtos/refresh-token.dto.js";
import { RefreshTokenResponseDto } from "../dtos/refresh-token-response.dto.js";
import type { ITokenService } from "../ports/token-service.interface.js";
import { TOKEN_SERVICE_TOKEN } from "../ports/token-service.interface.js";

@Injectable()
export class RefreshTokenUseCase {
  constructor(
    @Inject(TOKEN_SERVICE_TOKEN) private readonly tokenService: ITokenService,
    @Inject(USER_REPOSITORY_TOKEN)
    private readonly userRepository: IUserRepository,
  ) {}

  async execute(dto: RefreshTokenDto): Promise<RefreshTokenResponseDto> {
    const verifiedPayload = await this.tokenService.verifyAccessToken(
      dto.accessToken,
      true,
    );

    if (!verifiedPayload) throw new RefreshTokenIsInvalidException();

    const payload = this.tokenService.decodeAccessToken(dto.accessToken);
    if (!payload) throw new RefreshTokenIsInvalidException();

    const user = await this.userRepository.findById(payload.sub);
    if (!user) throw new UserNotFoundException(payload.sub);

    if (user.getRefreshToken() !== dto.refreshToken) {
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

      return {
        accessToken: newTokenPair.accessToken,
        refreshToken: newTokenPair.refreshToken,
      };
    } else {
      const accessToken = await this.tokenService.generateAccessToken({
        sub: user.getId(),
        username: user.getUsername(),
      });

      return {
        accessToken,
      };
    }
  }
}
