import { Inject, Injectable } from '@nestjs/common';
import type {
  RevokeIdentitySessionDto,
  RevokeIdentitySessionResultDto,
} from '../dtos/revoke-identity-session.dto.js';
import { LogoutIdentityUseCase } from './logout-identity.use-case.js';
import {
  IDENTITY_SESSION_STORE_TOKEN,
  type IIdentitySessionStore,
} from '../../domain/repositories/identity-session-store.js';

@Injectable()
export class RevokeIdentitySessionUseCase {
  constructor(
    @Inject(LogoutIdentityUseCase)
    private readonly logoutIdentityUseCase: LogoutIdentityUseCase,
    @Inject(IDENTITY_SESSION_STORE_TOKEN)
    private readonly store: IIdentitySessionStore,
  ) {}

  async execute(
    dto: RevokeIdentitySessionDto,
  ): Promise<RevokeIdentitySessionResultDto> {
    if (dto.sessionId) {
      const session = (await this.store.listAll()).find(
        (candidate) => candidate.getId() === dto.sessionId,
      );
      if (!session) return { removed: false };

      const sourceIp = session.getSourceIp().getValue;
      if (dto.sourceIp && dto.sourceIp !== sourceIp) return { removed: false };

      return this.logoutIdentityUseCase.execute({ sourceIp });
    }

    if (dto.sourceIp) {
      return this.logoutIdentityUseCase.execute({ sourceIp: dto.sourceIp });
    }

    return { removed: false };
  }
}
