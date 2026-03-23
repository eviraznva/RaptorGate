import { InvalidCredentialsException } from 'src/domain/exceptions/invalid-credentials.exception';
import type { IUserRepository } from 'src/domain/repositories/user.repository';
import { USER_REPOSITORY_TOKEN } from 'src/domain/repositories/user.repository';
import { PASSWORD_HASHER_TOKEN } from '../ports/passowrd-hasher.interface';
import type { IPasswordHasher } from '../ports/passowrd-hasher.interface';
import { TOKEN_SERVICE_TOKEN } from '../ports/token-service.interface';
import type { ITokenService } from '../ports/token-service.interface';
import { LoginResponseDto } from '../dtos/login-response.dto';
import { Inject, Injectable } from '@nestjs/common';
import { LoginDto } from '../dtos/login.dto';

@Injectable()
export class LoginUserUseCase {
  constructor(
    @Inject(USER_REPOSITORY_TOKEN)
    private readonly userRepository: IUserRepository,
    @Inject(PASSWORD_HASHER_TOKEN)
    private readonly passwordHasher: IPasswordHasher,
    @Inject(TOKEN_SERVICE_TOKEN) private readonly tokenService: ITokenService,
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

    return {
      id: user.getId(),
      username: user.getUsername(),
      createdAt: user.getCreatedAt(),
      accessToken: toknenPair.accessToken,
      refreshToken: toknenPair.refreshToken,
    };
  }
}
