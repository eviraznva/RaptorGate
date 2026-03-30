import {
  type IRecoveryTokenService,
  RECOVERY_TOKEN_SERVICE_TOKEN,
} from '../ports/recovery-token-service.interface';
import {
  type IUserRepository,
  USER_REPOSITORY_TOKEN,
} from 'src/domain/repositories/user.repository';
import {
  type IPasswordHasher,
  PASSWORD_HASHER_TOKEN,
} from '../ports/passowrd-hasher.interface';
import { Inject, Injectable } from '@nestjs/common';
import { RecoveryPasswordDto } from '../dtos/recovery-password.dto';
import { EntityNotFoundException } from 'src/domain/exceptions/entity-not-found-exception';

@Injectable()
export class RecoverPasswordUseCase {
  constructor(
    @Inject(USER_REPOSITORY_TOKEN)
    private readonly userRepository: IUserRepository,
    @Inject(RECOVERY_TOKEN_SERVICE_TOKEN)
    private readonly recoveryTokenService: IRecoveryTokenService,
    @Inject(PASSWORD_HASHER_TOKEN)
    private readonly passwordHasherService: IPasswordHasher,
  ) {}

  async execute(dto: RecoveryPasswordDto): Promise<void> {
    const user = await this.userRepository.findByUsername(dto.username);
    if (!user) throw new EntityNotFoundException('User', dto.username);

    if (!user.getRecoveryToken())
      throw new Error('No recovery token found for user');

    const isValidToken = await this.passwordHasherService.compare(
      dto.recoveryToken,
      user.getRecoveryToken()!,
    );

    if (!isValidToken) throw new Error('Invalid recovery token');

    const hashedPassword = await this.passwordHasherService.hash(
      dto.newPassword,
    );

    user.setPasswordHash(hashedPassword);
    user.setShowRecoveryToken(true);

    await this.userRepository.save(user);
  }
}
