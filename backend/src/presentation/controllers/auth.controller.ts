import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Inject,
  Post,
  Res,
} from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { ApiBody, ApiOperation, ApiTags } from "@nestjs/swagger";
import { Throttle } from "@nestjs/throttler";
import type { Response } from "express";
import { LoginUserUseCase } from "../../application/use-cases/login-user.use-case";
import { LogoutUserUseCase } from "../../application/use-cases/logout-user.use-case";
import { RecoverPasswordUseCase } from "../../application/use-cases/recover-password.use-case";
import { RefreshTokenUseCase } from "../../application/use-cases/refresh-token.use-case";
import { Cookie } from "../../infrastructure/decorators/cookie.decorator";
import { IsPublic } from "../../infrastructure/decorators/public.decorator";
import type { Env } from "../../shared/config/env.validation";
import {
  ApiCreatedEnvelope,
  ApiNoContentEnvelope,
} from "../decorators/api-envelope-response.decorator";
import {
  ApiError400,
  ApiError401,
  ApiError404,
  ApiError429,
  ApiError500,
} from "../decorators/api-error-response.decorator";
import { ExtractToken } from "../decorators/auth/extract-token.decorator";
import { ResponseMessage } from "../decorators/response-message.decorator";
import { LoginDto } from "../dtos/login.dto";
import { LoginResponseDto } from "../dtos/login-response.dto";
import { RecoveryPasswordDto } from "../dtos/recover-password.dto";
import { RefreshTokenResponseDto } from "../dtos/refresh-token-response.dto";

@ApiTags("Authentication")
@Controller("auth")
export class AuthController {
  constructor(
    @Inject(RefreshTokenUseCase)
    private readonly refreshTokenUseCase: RefreshTokenUseCase,
    @Inject(ConfigService)
    private readonly configService: ConfigService<Env, true>,
    @Inject(LogoutUserUseCase)
    private readonly logoutUserUseCase: LogoutUserUseCase,
    @Inject(LoginUserUseCase)
    private readonly loginUserUseCase: LoginUserUseCase,
    @Inject(RecoverPasswordUseCase)
    private readonly recoverPasswordUseCase: RecoverPasswordUseCase,
  ) {}

  @ApiOperation({
    summary: "User login",
    description:
      "Authenticates user with username and password, returns JWT access token",
  })
  @IsPublic()
  @Post("login")
  @HttpCode(HttpStatus.CREATED)
  @ApiBody({ type: LoginDto })
  @ResponseMessage("User logged in")
  @ApiCreatedEnvelope(LoginResponseDto, "User logged in")
  @ApiError400("Validation failed or invalid credentials")
  @ApiError429("Too many login attempts")
  @ApiError500()
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  async login(
    @Body() loginDto: LoginDto,
    @Res({ passthrough: true }) res: Response,
  ): Promise<LoginResponseDto> {
    const applicationDto = {
      username: loginDto.username,
      password: loginDto.password,
    };

    const { refreshToken, ...loginResponse } =
      await this.loginUserUseCase.execute(applicationDto);

    res.cookie("refresh_token", refreshToken, {
      httpOnly: true,
      secure:
        this.configService.get("NODE_ENV") === "development" ||
        this.configService.get("NODE_ENV") === "production",
      sameSite: "strict",
      maxAge: 60 * 60 * 1000,
      path: "/auth/refresh",
    });

    return loginResponse;
  }

  @IsPublic()
  @Post("refresh")
  @ApiOperation({
    summary: "Refresh JWT access token",
    description:
      "Refreshes JWT access token using a valid refresh token. The refresh token is expected to be sent as an HTTP-only cookie named 'refresh_token'. The current access token should be sent in the Authorization header as a Bearer token. If the refresh token is valid and not expired, a new access token will be issued. If the refresh token is close to expiring, a new refresh token will also be issued and set in the cookie.",
  })
  @ResponseMessage("Access token refreshed")
  @ApiCreatedEnvelope(RefreshTokenResponseDto, "Access token refreshed")
  @ApiError401("Authorization header missing/invalid or refresh token invalid")
  @ApiError404("User not found")
  @ApiError429("Too many requests")
  @ApiError500()
  async refresh(
    @ExtractToken() accessToken: string,
    @Cookie("refresh_token") refreshToken: string,
    @Res({ passthrough: true }) res: Response,
  ): Promise<RefreshTokenResponseDto> {
    const useCase = await this.refreshTokenUseCase.execute({
      refreshToken,
      accessToken,
    });

    if (useCase.refreshToken) {
      res.cookie("refresh_token", useCase.refreshToken, {
        httpOnly: true,
        secure:
          this.configService.get("NODE_ENV") === "development" ||
          this.configService.get("NODE_ENV") === "production",
        sameSite: "strict",
        maxAge: 60 * 60 * 1000,
        path: "/auth/refresh",
      });
    }

    return {
      accessToken: useCase.accessToken,
    };
  }

  @Post("logout")
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: "User logout",
    description:
      "Logs out the user by invalidating the current access token and clearing the refresh token cookie. The access token should be sent in the Authorization header as a Bearer token. Upon successful logout, the refresh token cookie will be cleared.",
  })
  @ResponseMessage("User logged out")
  @ApiNoContentEnvelope()
  @ApiError401("Missing or invalid token")
  @ApiError404("User not found")
  @ApiError429("Too many requests")
  @ApiError500()
  async logout(
    @ExtractToken() accessToken: string,
    @Res({ passthrough: true }) res: Response,
  ): Promise<void> {
    await this.logoutUserUseCase.execute({ accessToken });

    res.clearCookie("refresh_token", {
      httpOnly: true,
      secure:
        this.configService.get("NODE_ENV") === "development" ||
        this.configService.get("NODE_ENV") === "production",
      sameSite: "strict",
      maxAge: 60 * 60 * 1000,
      path: "/auth/refresh",
    });
  }

  @IsPublic()
  @Post("recover-password")
  @ApiOperation({
    summary: "Password recovery",
    description:
      "Recovery password using a valid recovery token. This endpoint allows users to reset their password by providing a valid recovery token, their username, and a new password. The recovery token is typically generated and sent to the user via email when they initiate a password recovery request. The user must provide the same username that was used to generate the recovery token. If the provided information is valid, the user's password will be updated to the new password.",
  })
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiBody({ type: RecoveryPasswordDto })
  @ResponseMessage("Password recovered")
  @ApiNoContentEnvelope()
  @ApiError400("Validation failed or invalid recovery token")
  @ApiError404("User not found")
  @ApiError429("Too many requests")
  @ApiError500("Server error while recovering password")
  async recoverPassword(@Body() dto: RecoveryPasswordDto): Promise<void> {
    await this.recoverPasswordUseCase.execute(dto);
  }
}
