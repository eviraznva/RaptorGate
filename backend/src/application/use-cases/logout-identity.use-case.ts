import { Inject, Injectable, Logger } from '@nestjs/common';
import {
  IDENTITY_SESSION_STORE_TOKEN,
  type IIdentitySessionStore,
} from '../../domain/repositories/identity-session-store.js';
import { IpAddress } from '../../domain/value-objects/ip-address.vo.js';
import {
  IDENTITY_SESSION_SYNC_SERVICE_TOKEN,
  type IIdentitySessionSyncService,
} from '../ports/identity-session-sync-service.interface.js';
import { LogoutIdentityDto } from '../dtos/logout-identity.dto.js';

export interface LogoutIdentityResult {
  removed: boolean;
}

@Injectable()
export class LogoutIdentityUseCase {
  private readonly logger = new Logger(LogoutIdentityUseCase.name);

  constructor(
    @Inject(IDENTITY_SESSION_STORE_TOKEN)
    private readonly store: IIdentitySessionStore,
    @Inject(IDENTITY_SESSION_SYNC_SERVICE_TOKEN)
    private readonly sync: IIdentitySessionSyncService,
  ) {}

  async execute(dto: LogoutIdentityDto): Promise<LogoutIdentityResult> {
    const sourceIp = IpAddress.create(dto.sourceIp);

    return this.store.runExclusiveBySourceIp(sourceIp.getValue, async () => {
      const firewallRemoved = await this.sync.revokeIdentitySession(sourceIp.getValue);
      const removed = await this.store.removeBySourceIp(sourceIp.getValue);

      this.logger.log({
        event: 'identity.session.revoked',
        message: 'identity session revoke processed',
        sourceIp: sourceIp.getValue,
        backendHadSession: removed !== null,
        firewallHadSession: firewallRemoved,
        sessionId: removed?.getId() ?? null,
        username: removed?.getUsername() ?? null,
      });

      return { removed: removed !== null || firewallRemoved };
    });
  }
}
