import { AccessTokenIsInvalidException } from '../../domain/exceptions/acces-token-is-invalid.exception.js';
import { UserNotFoundException } from '../../domain/exceptions/user-not-found.exception.js';
import { USER_REPOSITORY_TOKEN } from '../../domain/repositories/user.repository.js';
import type { IUserRepository } from '../../domain/repositories/user.repository.js';
import { TOKEN_SERVICE_TOKEN } from '../ports/token-service.interface.js';
import type { ITokenService } from '../ports/token-service.interface.js';
import { LogoutUserDto } from '../dtos/logout-user.dto.js';
import { Inject, Injectable, Logger } from '@nestjs/common';

@Injectable()
export class LogoutUserUseCase {
  private readonly logger = new Logger(LogoutUserUseCase.name);

  constructor(
    @Inject(USER_REPOSITORY_TOKEN)
    private readonly userRepository: IUserRepository,
    @Inject(TOKEN_SERVICE_TOKEN) private readonly tokenService: ITokenService,
  ) {}

  async execute(dto: LogoutUserDto): Promise<void> {
    const verifiedToken = await this.tokenService.verifyAccessToken(
      dto.accessToken,
    );

    if (!verifiedToken) throw new AccessTokenIsInvalidException();

    const payload = this.tokenService.decodeAccessToken(dto.accessToken);

    if (!payload) throw new AccessTokenIsInvalidException();

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
      event: 'auth.logout.succeeded',
      message: 'user logged out',
      userId: user.getId(),
      username: user.getUsername(),
    });
  }
}
