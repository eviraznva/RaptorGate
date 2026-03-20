import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Inject,
  Post,
  Res,
  UseFilters,
} from '@nestjs/common';
import {
  ErrorResponseDto,
  ValidationErrorResponseDto,
} from '../dtos/error-response.dto';
import { RefreshTokenUseCase } from 'src/application/use-cases/refresh-token.use-case';
import { ExtractToken } from 'src/infrastructure/decorators/extract-token.decorator';
import { LogoutUserUseCase } from 'src/application/use-cases/logout-user.use-case';
import { LoginUserUseCase } from 'src/application/use-cases/login-user.use-case';
import { ApiTags, ApiOperation, ApiResponse, ApiBody } from '@nestjs/swagger';
import { RefreshTokenResponseDto } from '../dtos/refresh-token-response.dto';
import { DomainExceptionFilter } from '../filters/domain-exception.filter';
import { IsPublic } from 'src/infrastructure/decorators/public.decorator';
import { Cookie } from 'src/infrastructure/decorators/cookie.decorator';
import { LoginResponseDto } from '../dtos/login-response.dto';
import { Env } from 'src/shared/config/env.validation';
import { ConfigService } from '@nestjs/config';
import { LoginDto } from '../dtos/login.dto';
import { Throttle } from '@nestjs/throttler';
import type { Response } from 'express';

@UseFilters(DomainExceptionFilter)
@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  constructor(
    @Inject() private readonly refreshTokenUseCase: RefreshTokenUseCase,
    @Inject() private readonly configService: ConfigService<Env, true>,
    @Inject() private readonly logoutUserUseCase: LogoutUserUseCase,
    @Inject() private readonly loginUserUseCase: LoginUserUseCase,
  ) {}

  @IsPublic()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'User login',
    description:
      'Authenticates user with username and password, returns JWT access token',
  })
  @ApiBody({ type: LoginDto })
  @ApiResponse({
    status: 200,
    description: 'Login successful',
    type: LoginResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Validation error - invalid request body',
    type: ValidationErrorResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Invalid credentials',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: 500,
    description: 'Internal server error',
  })
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

    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure:
        this.configService.get('NODE_ENV') === 'development' ||
        this.configService.get('NODE_ENV') === 'production',
      sameSite: 'strict',
      maxAge: 60 * 60 * 1000,
      path: '/auth/refresh',
    });

    return loginResponse;
  }

  @ApiOperation({
    summary: 'Refresh JWT access token',
    description:
      "Refreshes JWT access token using a valid refresh token. The refresh token is expected to be sent as an HTTP-only cookie named 'refresh_token'. The current access token should be sent in the Authorization header as a Bearer token. If the refresh token is valid and not expired, a new access token will be issued. If the refresh token is close to expiring, a new refresh token will also be issued and set in the cookie.",
  })
  @ApiResponse({
    status: 201,
    description: 'Access token refreshed successfully',
    type: RefreshTokenResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid access token format or missing refresh token cookie',
  })
  @ApiResponse({
    status: 500,
    description: 'Internal server error',
  })
  @IsPublic()
  @Post('refresh')
  async refresh(
    @ExtractToken() accessToken: string,
    @Cookie('refresh_token') refreshToken: string,
    @Res({ passthrough: true }) res: Response,
  ): Promise<RefreshTokenResponseDto> {
    const useCase = await this.refreshTokenUseCase.execute({
      refreshToken,
      accessToken,
    });

    if (useCase.refreshToken) {
      res.cookie('refresh_token', useCase.refreshToken, {
        httpOnly: true,
        secure:
          this.configService.get('NODE_ENV') === 'development' ||
          this.configService.get('NODE_ENV') === 'production',
        sameSite: 'strict',
        maxAge: 60 * 60 * 1000,
        path: '/auth/refresh',
      });
    }

    return {
      accessToken: useCase.accessToken,
    };
  }

  @ApiOperation({
    summary: 'User logout',
    description:
      'Logs out the user by invalidating the current access token and clearing the refresh token cookie. The access token should be sent in the Authorization header as a Bearer token. Upon successful logout, the refresh token cookie will be cleared.',
  })
  @ApiResponse({
    status: 201,
    description: 'User logged out',
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid access token format',
  })
  @ApiResponse({
    status: 500,
    description: 'Internal server error',
  })
  @Post('logout')
  async logout(
    @ExtractToken() accessToken: string,
    @Res({ passthrough: true }) res: Response,
  ): Promise<void> {
    await this.logoutUserUseCase.execute({ accessToken });

    res.clearCookie('refresh_token', {
      httpOnly: true,
      secure:
        this.configService.get('NODE_ENV') === 'development' ||
        this.configService.get('NODE_ENV') === 'production',
      sameSite: 'strict',
      maxAge: 60 * 60 * 1000,
      path: '/auth/refresh',
    });
  }
}
