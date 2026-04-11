import { Inject, Injectable } from '@nestjs/common';
import { InvalidCredentialsException } from '../../domain/exceptions/invalid-credentials.exception.js';
import type { IUserRepository } from '../../domain/repositories/user.repository.js';
import { USER_REPOSITORY_TOKEN } from '../../domain/repositories/user.repository.js';
import { LoginDto } from '../dtos/login.dto.js';
import { LoginResponseDto } from '../dtos/login-response.dto.js';
import type { IPasswordHasher } from '../ports/passowrd-hasher.interface.js';
import { PASSWORD_HASHER_TOKEN } from '../ports/passowrd-hasher.interface.js';
import type { IRecoveryTokenService } from '../ports/recovery-token-service.interface.js';
import { RECOVERY_TOKEN_SERVICE_TOKEN } from '../ports/recovery-token-service.interface.js';
import type { ITokenService } from '../ports/token-service.interface.js';
import { TOKEN_SERVICE_TOKEN } from '../ports/token-service.interface.js';

@Injectable()
export class LoginUserUseCase {
  constructor(
    @Inject(USER_REPOSITORY_TOKEN)
    private readonly userRepository: IUserRepository,
    @Inject(PASSWORD_HASHER_TOKEN)
    private readonly passwordHasher: IPasswordHasher,
    @Inject(TOKEN_SERVICE_TOKEN) private readonly tokenService: ITokenService,
    @Inject(RECOVERY_TOKEN_SERVICE_TOKEN)
    private readonly recoveryTokenService: IRecoveryTokenService,
  ) {}

  async execute(dto: LoginDto): Promise<LoginResponseDto> {
    const user = await this.userRepository.findByUsername(dto.username);

    if (!user) throw new InvalidCredentialsException();

    const isPasswordValid = await this.passwordHasher.compare(
      dto.password,
      user.getPasswordHash(),
    );

    if (!isPasswordValid) throw new InvalidCredentialsException();

    const toknenPair = await this.tokenService.generateTokenPair({
      sub: user.getId(),
      username: user.getUsername(),
    });

    const refreshTokenExpiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    user.setRefreshToken(toknenPair.refreshToken);
    user.setRefreshTokenExpiry(refreshTokenExpiry);

    await this.userRepository.setRefreshToken(
      user.getId(),
      toknenPair.refreshToken,
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
      accessToken: toknenPair.accessToken,
      refreshToken: toknenPair.refreshToken,
      recoveryToken: user.getShowRecoveryToken() ? recoveryToken : null,
      isFirstLogin: user.getIsFirstLogin(),
      showRecoveryToken: user.getShowRecoveryToken(),
    };

    user.setIsFirstLogin(false);
    user.setShowRecoveryToken(false);

    if (!user.getShowRecoveryToken() && !user.getIsFirstLogin()) {
      await this.userRepository.save(user);
    }

    return loggedInUser;
  }
}
