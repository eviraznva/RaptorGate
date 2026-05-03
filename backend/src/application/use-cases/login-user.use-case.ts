import { Inject, Injectable, Logger } from "@nestjs/common";
import { AdminAuthSession } from "../../domain/entities/admin-auth-session.entity.js";
import { AuthenticationMisconfiguredException } from "../../domain/exceptions/authentication-misconfigured.exception.js";
import { AuthenticationUnavailableException } from "../../domain/exceptions/authentication-unavailable.exception.js";
import { InvalidCredentialsException } from "../../domain/exceptions/invalid-credentials.exception.js";
import {
  ADMIN_AUTH_SESSION_REPOSITORY_TOKEN,
  type IAdminAuthSessionRepository,
} from "../../domain/repositories/admin-auth-session.repository.js";
import type { IUserRepository } from "../../domain/repositories/user.repository.js";
import { USER_REPOSITORY_TOKEN } from "../../domain/repositories/user.repository.js";
import type { IRoleRepository } from "../../domain/repositories/role.repository.js";
import { ROLE_REPOSITORY_TOKEN } from "../../domain/repositories/role.repository.js";
import { LoginDto } from "../dtos/login.dto.js";
import { LoginResponseDto } from "../dtos/login-response.dto.js";
import type { IPasswordHasher } from "../ports/passowrd-hasher.interface.js";
import { PASSWORD_HASHER_TOKEN } from "../ports/passowrd-hasher.interface.js";
import type { IRecoveryTokenService } from "../ports/recovery-token-service.interface.js";
import { RECOVERY_TOKEN_SERVICE_TOKEN } from "../ports/recovery-token-service.interface.js";
import type { ITokenService } from "../ports/token-service.interface.js";
import { TOKEN_SERVICE_TOKEN } from "../ports/token-service.interface.js";
import { AdminAuthorizationService } from "../services/admin-authorization.service.js";
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
    @Inject(AdminAuthorizationService)
    private readonly adminAuthorization: AdminAuthorizationService,
    @Inject(ADMIN_AUTH_SESSION_REPOSITORY_TOKEN)
    private readonly adminAuthSessionRepository: IAdminAuthSessionRepository,
    @Inject(ROLE_REPOSITORY_TOKEN)
    private readonly roleRepository: IRoleRepository,
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

    if (externalResult.provider === "local") {
      throw new InvalidCredentialsException();
    }

    const authorization = await this.adminAuthorization.authorize(externalResult);
    if (authorization.kind === "misconfigured") {
      throw new AuthenticationMisconfiguredException(authorization.reason);
    }
    if (authorization.kind === "denied") {
      throw new InvalidCredentialsException();
    }

    return this.completeExternalLogin(externalResult, authorization.role);
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

    const userRoles = await this.roleRepository.findByUserId(user.getId());

    const loggedInUser = {
      id: user.getId(),
      username: user.getUsername(),
      createdAt: user.getCreatedAt(),
      accessToken: tokenPair.accessToken,
      refreshToken: tokenPair.refreshToken,
      recoveryToken: user.getShowRecoveryToken() ? recoveryToken : null,
      isFirstLogin: user.getIsFirstLogin(),
      showRecoveryToken: user.getShowRecoveryToken(),
      roles: userRoles.map((role) => role.getName()),
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

  private async completeExternalLogin(
    result: Extract<
      Awaited<ReturnType<AuthenticationEngineService["authenticate"]>>,
      { kind: "accept" }
    >,
    role: "super_admin" | "admin" | "operator" | "viewer",
  ): Promise<LoginResponseDto> {
    if (result.provider !== "radius" && result.provider !== "ldap") {
      throw new InvalidCredentialsException();
    }
    const provider = result.provider;
    const now = new Date();
    const sessionId = crypto.randomUUID();
    const refreshTokenExpiry = new Date(now.getTime() + 60 * 60 * 1000);
    const tokenPair = await this.tokenService.generateTokenPair({
      sub: sessionId,
      username: result.username,
      principalType: "external_admin",
      roles: [role],
      authProvider: provider,
      authProfileId: result.profileId,
      externalId: result.externalId,
    });
    const refreshTokenHash = await this.passwordHasher.hash(tokenPair.refreshToken);

    const session = AdminAuthSession.create(
      sessionId,
      result.username,
      provider,
      result.profileId,
      result.externalId,
      [role],
      refreshTokenHash,
      refreshTokenExpiry,
      now,
      now,
      null,
    );

    await this.adminAuthSessionRepository.save(session);

    this.logger.log({
      event: "auth.admin.external_login.succeeded",
      message: "external admin logged in with mapped role",
      sessionId,
      username: result.username,
      provider,
      profileId: result.profileId,
      role,
    });

    return {
      id: sessionId,
      username: result.username,
      createdAt: now,
      accessToken: tokenPair.accessToken,
      refreshToken: tokenPair.refreshToken,
      recoveryToken: null,
      isFirstLogin: false,
      showRecoveryToken: false,
      roles: [role],
      authProvider: provider,
      authProfileId: result.profileId,
    };
  }
}
