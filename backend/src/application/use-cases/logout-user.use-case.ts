import { AccessTokenIsInvalidException } from '../../domain/exceptions/acces-token-is-invalid.exception';
import { UserNotFoundException } from '../../domain/exceptions/user-not-found.exception';
import { USER_REPOSITORY_TOKEN } from '../../domain/repositories/user.repository';
import type { IUserRepository } from '../../domain/repositories/user.repository';
import { TOKEN_SERVICE_TOKEN } from '../ports/token-service.interface';
import type { ITokenService } from '../ports/token-service.interface';
import { LogoutUserDto } from '../dtos/logout-user.dto';
import { Inject, Injectable } from '@nestjs/common';

@Injectable()
export class LogoutUserUseCase {
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
  }
}
