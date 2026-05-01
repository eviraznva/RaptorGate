import {
  Inject,
  Injectable,
  Logger,
  type OnModuleDestroy,
  type OnModuleInit,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  IDENTITY_SESSION_SYNC_SERVICE_TOKEN,
  type IIdentitySessionSyncService,
} from '../../application/ports/identity-session-sync-service.interface.js';
import { AuthenticationGroupResolverService } from '../../application/services/authentication-group-resolver.service.js';
import { AuthenticationProfileResolverService } from '../../application/services/authentication-profile-resolver.service.js';
import type { IdentitySession } from '../../domain/entities/identity-session.entity.js';
import {
  IDENTITY_SESSION_STORE_TOKEN,
  type IIdentitySessionStore,
} from '../../domain/repositories/identity-session-store.js';
import type { Env } from '../../shared/config/env.validation.js';

const PLACEHOLDER_MAC = '00:00:00:00:00:00';

// Odswieza grupy aktywnych sesji bez relogowania.
@Injectable()
export class IdentityGroupRefresherService
  implements OnModuleInit, OnModuleDestroy
{
  private readonly logger = new Logger(IdentityGroupRefresherService.name);
  private timer: NodeJS.Timeout | null = null;
  private running = false;

  constructor(
    @Inject(ConfigService)
    private readonly config: ConfigService<Env, true>,
    @Inject(IDENTITY_SESSION_STORE_TOKEN)
    private readonly store: IIdentitySessionStore,
    @Inject(IDENTITY_SESSION_SYNC_SERVICE_TOKEN)
    private readonly sync: IIdentitySessionSyncService,
    @Inject(AuthenticationProfileResolverService)
    private readonly profileResolver: AuthenticationProfileResolverService,
    @Inject(AuthenticationGroupResolverService)
    private readonly groupResolver: AuthenticationGroupResolverService,
  ) {}

  onModuleInit(): void {
    const intervalMs = this.config.get('IDENTITY_GROUP_REFRESH_INTERVAL_MS', {
      infer: true,
    });
    if (intervalMs <= 0) return;

    this.timer = setInterval(() => {
      void this.refreshOnce();
    }, intervalMs);
    this.timer.unref?.();
  }

  onModuleDestroy(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  async refreshOnce(): Promise<void> {
    if (this.running) return;
    this.running = true;
    try {
      const sessions = await this.store.listAll();
      for (const session of sessions) {
        await this.refreshSession(session);
      }
    } finally {
      this.running = false;
    }
  }

  private async refreshSession(session: IdentitySession): Promise<void> {
    const username = session.getUsername();
    const ip = session.getSourceIp().getValue;

    const profile = await this.profileResolver.resolve('portal');
    if (profile.kind !== 'resolved') return;

    const resolution = await this.groupResolver.resolve(
      profile,
      username,
      [],
    );
    if (
      resolution.diagnostic === 'disabled' ||
      resolution.diagnostic === 'skipped' ||
      resolution.source === 'none'
    ) {
      return;
    }

    if (sameGroups(session.getGroups(), resolution.groups)) {
      return;
    }

    await this.store.runExclusiveBySourceIp(ip, async () => {
      const live = await this.store.findBySourceIp(ip);
      if (!live || live.getId() !== session.getId()) return;
      if (sameGroups(live.getGroups(), resolution.groups)) return;

      try {
        await this.sync.upsertIdentitySession({
          id: live.getId(),
          identityUserId: resolution.externalId,
          radiusUsername: username,
          macAddress: PLACEHOLDER_MAC,
          ipAddress: ip,
          nasIp: live.getNasIp(),
          calledStationId: live.getCalledStationId(),
          authenticatedAt: live.getCreatedAt(),
          expiresAt: live.getExpiresAt(),
          groups: resolution.groups,
        });
        live.replaceGroups(resolution.groups);

        this.logger.log({
          event: 'identity.groups.refreshed',
          message: 'identity session groups refreshed and pushed to firewall',
          sessionId: live.getId(),
          username,
          sourceIp: ip,
          source: resolution.source,
          groupCount: resolution.groups.length,
        });
      } catch (error) {
        const message =
          error instanceof Error ? error.message : 'unknown error';
        this.logger.error({
          event: 'identity.groups.refresh_failed',
          message: 'failed to push refreshed groups to firewall',
          sessionId: live.getId(),
          username,
          sourceIp: ip,
          error: message,
        });
      }
    });
  }
}

function sameGroups(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false;
  const sortedA = [...a].sort();
  const sortedB = [...b].sort();
  for (let i = 0; i < sortedA.length; i += 1) {
    if (sortedA[i] !== sortedB[i]) return false;
  }
  return true;
}
