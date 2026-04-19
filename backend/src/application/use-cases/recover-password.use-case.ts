import { Inject, Injectable, Logger } from "@nestjs/common";
import { EntityNotFoundException } from "src/domain/exceptions/entity-not-found-exception";
import {
  type IUserRepository,
  USER_REPOSITORY_TOKEN,
} from "src/domain/repositories/user.repository";
import type { RecoveryPasswordDto } from "../dtos/recovery-password.dto";
import {
  type IPasswordHasher,
  PASSWORD_HASHER_TOKEN,
} from "../ports/passowrd-hasher.interface";
import {
  type IRecoveryTokenService,
  RECOVERY_TOKEN_SERVICE_TOKEN,
} from "../ports/recovery-token-service.interface";

@Injectable()
export class RecoverPasswordUseCase {
  private readonly logger = new Logger(RecoverPasswordUseCase.name);

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
    if (!user) {
      this.logger.warn({
        event: "auth.password_recovery.failed",
        message: "password recovery failed for unknown user",
        username: dto.username,
      });
      throw new EntityNotFoundException("User", dto.username);
    }

    if (user.getRecoveryToken() === null) {
      this.logger.warn({
        event: "auth.password_recovery.failed",
        message: "password recovery token is not set",
        userId: user.getId(),
        username: user.getUsername(),
      });
      throw new Error("No recovery token found for user");
    }

    const isValidToken = await this.passwordHasherService.compare(
      dto.recoveryToken,
      user.getRecoveryToken()!,
    );

    if (!isValidToken) {
      this.logger.warn({
        event: "auth.password_recovery.failed",
        message: "invalid recovery token",
        userId: user.getId(),
        username: user.getUsername(),
      });
      throw new Error("Invalid recovery token");
    }

    const hashedPassword = await this.passwordHasherService.hash(
      dto.newPassword,
    );

    user.setPasswordHash(hashedPassword);
    user.setShowRecoveryToken(true);

    await this.userRepository.save(user);

    this.logger.log({
      event: "auth.password_recovery.succeeded",
      message: "password recovered",
      userId: user.getId(),
      username: user.getUsername(),
    });
  }
}
