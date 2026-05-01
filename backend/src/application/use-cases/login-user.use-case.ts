import { Inject, Injectable, Logger } from "@nestjs/common";
import { AuthenticationMisconfiguredException } from "../../domain/exceptions/authentication-misconfigured.exception.js";
import { AuthenticationUnavailableException } from "../../domain/exceptions/authentication-unavailable.exception.js";
import { InvalidCredentialsException } from "../../domain/exceptions/invalid-credentials.exception.js";
import type { IUserRepository } from "../../domain/repositories/user.repository.js";
import { USER_REPOSITORY_TOKEN } from "../../domain/repositories/user.repository.js";
import { LoginDto } from "../dtos/login.dto.js";
import { LoginResponseDto } from "../dtos/login-response.dto.js";
import type { IPasswordHasher } from "../ports/passowrd-hasher.interface.js";
import { PASSWORD_HASHER_TOKEN } from "../ports/passowrd-hasher.interface.js";
import type { IRecoveryTokenService } from "../ports/recovery-token-service.interface.js";
import { RECOVERY_TOKEN_SERVICE_TOKEN } from "../ports/recovery-token-service.interface.js";
import type { ITokenService } from "../ports/token-service.interface.js";
import { TOKEN_SERVICE_TOKEN } from "../ports/token-service.interface.js";
import { AuthenticationEngineService } from "../services/authentication-engine.service.js";
import { User } from "../../domain/entities/user.entity.js";

@Injectable()
export class LoginUserUseCase {
  private readonly logger = new Logger(LoginUserUseCase.name);

  constructor(
    @Inject(USER_REPOSITORY_TOKEN)
    private readonly userRepository: IUserRepository,
    @Inject(PASSWORD_HASHER_TOKEN)
    private readonly passwordHasher: IPasswordHasher,
    @Inject(TOKEN_SERVICE_TOKEN) private readonly tokenService: ITokenService,
    @Inject(RECOVERY_TOKEN_SERVICE_TOKEN)
    private readonly recoveryTokenService: IRecoveryTokenService,
    @Inject(AuthenticationEngineService)
    private readonly authenticationEngine: AuthenticationEngineService,
  ) {}

  async execute(dto: LoginDto): Promise<LoginResponseDto> {
    const user = await this.userRepository.findByUsername(dto.username);

    if (user) {
      // Lokalny break-glass zawsze ma pierwszenstwo przed providerem zewnetrznym.
      const isPasswordValid = await this.passwordHasher.compare(
        dto.password,
        user.getPasswordHash(),
      );

      if (isPasswordValid) {
        return this.completeLogin(user, "local");
      }

      this.logger.warn({
        event: "auth.login.failed",
        message: "login failed for invalid local password",
        userId: user.getId(),
        username: user.getUsername(),
      });
    } else {
      this.logger.warn({
        event: "auth.login.failed",
        message: "login failed for unknown local user",
        username: dto.username,
      });
    }

    let externalResult;
    try {
      externalResult = await this.authenticationEngine.authenticate({
        flow: "admin",
        username: dto.username,
        password: dto.password,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : "unknown error";
      this.logger.error({
        event: "auth.admin.external_error",
        message: "external admin authentication failed before result",
        username: dto.username,
        error: message,
      });
      if (user) {
        if (
          error instanceof AuthenticationUnavailableException ||
          error instanceof AuthenticationMisconfiguredException
        ) {
          throw error;
        }
        throw new AuthenticationMisconfiguredException(message);
      }
      throw new InvalidCredentialsException();
    }

    if (externalResult.kind !== "accept") {
      this.logger.warn({
        event: "auth.admin.external_rejected",
        message: "external admin authentication did not accept credentials",
        username: dto.username,
        result: externalResult.kind,
        provider: "provider" in externalResult ? externalResult.provider : undefined,
      });
      if (!user) {
        throw new InvalidCredentialsException();
      }
      if (
        externalResult.kind === "timeout" ||
        externalResult.kind === "unavailable"
      ) {
        throw new AuthenticationUnavailableException(externalResult.message);
      }
      if (externalResult.kind === "misconfigured") {
        throw new AuthenticationMisconfiguredException(externalResult.message);
      }
      throw new InvalidCredentialsException();
    }

    if (!user) {
      this.logger.warn({
        event: "auth.admin.external_unmapped",
        message: "external admin authentication accepted but no local user mapping exists",
        username: dto.username,
        provider: externalResult.provider,
      });
      throw new InvalidCredentialsException();
    }

    return this.completeLogin(user, externalResult.provider);
  }

  private async completeLogin(
    user: User,
    provider: string,
  ): Promise<LoginResponseDto> {
    const tokenPair = await this.tokenService.generateTokenPair({
      sub: user.getId(),
      username: user.getUsername(),
    });

    const refreshTokenExpiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    user.setRefreshToken(tokenPair.refreshToken);
    user.setRefreshTokenExpiry(refreshTokenExpiry);

    await this.userRepository.setRefreshToken(
      user.getId(),
      tokenPair.refreshToken,
      refreshTokenExpiry,
    );

    let recoveryToken: string | null = null;

    if (user.getShowRecoveryToken()) {
      recoveryToken = this.recoveryTokenService.createRecoveryToken(256);
      const hashedRecoveryToken = await this.passwordHasher.hash(recoveryToken);
      user.setRecoveryToken(hashedRecoveryToken);
      user.setShowRecoveryToken(true);

      await this.userRepository.save(user);
    }

    const loggedInUser = {
      id: user.getId(),
      username: user.getUsername(),
      createdAt: user.getCreatedAt(),
      accessToken: tokenPair.accessToken,
      refreshToken: tokenPair.refreshToken,
      recoveryToken: user.getShowRecoveryToken() ? recoveryToken : null,
      isFirstLogin: user.getIsFirstLogin(),
      showRecoveryToken: user.getShowRecoveryToken(),
    };

    user.setIsFirstLogin(false);
    user.setShowRecoveryToken(false);

    if (!user.getShowRecoveryToken() && !user.getIsFirstLogin()) {
      await this.userRepository.save(user);
    }

    this.logger.log({
      event: "auth.login.succeeded",
      message: "user logged in",
      userId: user.getId(),
      username: user.getUsername(),
      provider,
      recoveryTokenIssued: recoveryToken !== null,
    });

    return loggedInUser;
  }
}
