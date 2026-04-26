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
import { IdentityGroupResolverService } from '../../application/services/identity-group-resolver.service.js';
import type { IdentitySession } from '../../domain/entities/identity-session.entity.js';
import {
  IDENTITY_SESSION_STORE_TOKEN,
  type IIdentitySessionStore,
} from '../../domain/repositories/identity-session-store.js';
import type { Env } from '../../shared/config/env.validation.js';

const PLACEHOLDER_MAC = '00:00:00:00:00:00';

// Refresher grup dla aktywnych sesji (Issue 4, ADR 0005). Dzieki niemu zmiana
// grupy uzytkownika w LDAP propaguje sie do polityk firewalla bez relogowania:
// resolver -> nowe grupy -> upsert (renew) tej samej sesji do firewalla.
// Cache LDAP starzeje sie wlasnym TTL, wiec nie odpytujemy LDAP-a co tick —
// odpytujemy tylko gdy cache miss.
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
    @Inject(IdentityGroupResolverService)
    private readonly resolver: IdentityGroupResolverService,
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

  // Wystawione publicznie dla testow i Issue 8 (manualny trigger z UI).
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

    // Refresh nie zna VSA — VSA jest shortcutem znanym tylko w momencie loginu.
    // Po Issue 4 LDAP jest source of truth, wiec brak VSA tutaj jest OK.
    const resolution = await this.resolver.resolve({ username, vsaGroups: [] });
    if (
      resolution.ldapDiagnostic === 'disabled' ||
      resolution.ldapDiagnostic === 'skipped' ||
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

      const nasIp = this.config.get('RADIUS_NAS_IP', { infer: true });
      const nasIdentifier = this.config.get('RADIUS_NAS_IDENTIFIER', {
        infer: true,
      });
      try {
        await this.sync.upsertIdentitySession({
          id: live.getId(),
          identityUserId: resolution.externalId,
          radiusUsername: username,
          macAddress: PLACEHOLDER_MAC,
          ipAddress: ip,
          nasIp,
          calledStationId: nasIdentifier,
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
