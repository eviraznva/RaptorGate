import { Inject, Injectable } from '@nestjs/common';
import type { ListIdentitySessionsDto } from '../dtos/list-identity-sessions.dto.js';
import {
  IDENTITY_SESSION_STORE_TOKEN,
  type IIdentitySessionStore,
} from '../../domain/repositories/identity-session-store.js';

@Injectable()
export class ListIdentitySessionsUseCase {
  constructor(
    @Inject(IDENTITY_SESSION_STORE_TOKEN)
    private readonly store: IIdentitySessionStore,
  ) {}

  async execute(): Promise<ListIdentitySessionsDto> {
    const now = new Date();
    const sessions = (await this.store.listAll()).filter(
      (session) => !session.isExpiredAt(now),
    );

    return {
      identitySessions: sessions.map((session) => ({
        sessionId: session.getId(),
        sourceIp: session.getSourceIp().getValue,
        username: session.getUsername(),
        groups: session.getGroups(),
        createdAt: session.getCreatedAt(),
        expiresAt: session.getExpiresAt(),
      })),
    };
  }
}
