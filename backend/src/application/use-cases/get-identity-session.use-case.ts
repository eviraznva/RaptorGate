import { Inject, Injectable } from '@nestjs/common';
import {
  IDENTITY_SESSION_STORE_TOKEN,
  type IIdentitySessionStore,
} from '../../domain/repositories/identity-session-store.js';
import { IpAddress } from '../../domain/value-objects/ip-address.vo.js';
import { GetIdentitySessionDto } from '../dtos/get-identity-session.dto.js';
import { GetIdentitySessionResponseDto } from '../dtos/get-identity-session-response.dto.js';

// Issue 7: portal pyta o aktualny stan sesji per source IP, zeby pokazac
// "already authenticated" zamiast formularza loginu.
@Injectable()
export class GetIdentitySessionUseCase {
  constructor(
    @Inject(IDENTITY_SESSION_STORE_TOKEN)
    private readonly store: IIdentitySessionStore,
  ) {}

  async execute(
    dto: GetIdentitySessionDto,
  ): Promise<GetIdentitySessionResponseDto> {
    const sourceIp = IpAddress.create(dto.sourceIp);
    const session = await this.store.findBySourceIp(sourceIp.getValue);

    if (!session || session.isExpiredAt(new Date())) {
      return { authenticated: false, sourceIp: sourceIp.getValue };
    }

    return {
      authenticated: true,
      sourceIp: sourceIp.getValue,
      sessionId: session.getId(),
      username: session.getUsername(),
      authenticatedAt: session.getCreatedAt(),
      expiresAt: session.getExpiresAt(),
      groups: session.getGroups(),
    };
  }
}
