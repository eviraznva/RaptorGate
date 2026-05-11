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
import type { IdentitySession } from '../../domain/entities/identity-session.entity.js';
import {
  IDENTITY_SESSION_STORE_TOKEN,
  type IIdentitySessionStore,
} from '../../domain/repositories/identity-session-store.js';
import type { Env } from '../../shared/config/env.validation.js';

@Injectable()
export class IdentitySessionReplayService
  implements OnModuleInit, OnModuleDestroy
{
  private readonly logger = new Logger(IdentitySessionReplayService.name);
  private timer: NodeJS.Timeout | null = null;
  private running = false;

  constructor(
    @Inject(ConfigService)
    private readonly config: ConfigService<Env, true>,
    @Inject(IDENTITY_SESSION_STORE_TOKEN)
    private readonly store: IIdentitySessionStore,
    @Inject(IDENTITY_SESSION_SYNC_SERVICE_TOKEN)
    private readonly sync: IIdentitySessionSyncService,
  ) {}

  onModuleInit(): void {
    void this.replayOnce();
    const intervalMs = this.config.get('IDENTITY_SESSION_REPLAY_INTERVAL_MS', {
      infer: true,
    });
    if (intervalMs <= 0) return;

    this.timer = setInterval(() => {
      void this.replayOnce();
    }, intervalMs);
    this.timer.unref?.();
  }

  onModuleDestroy(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  async replayOnce(now: Date = new Date()): Promise<void> {
    if (this.running) return;
    this.running = true;
    try {
      const sessions = await this.store.listAll();
      for (const session of sessions) {
        await this.replaySession(session, now);
      }
    } finally {
      this.running = false;
    }
  }

  private async replaySession(session: IdentitySession, now: Date): Promise<void> {
    if (session.isExpiredAt(now)) return;
    const ip = session.getSourceIp().getValue;

    await this.store.runExclusiveBySourceIp(ip, async () => {
      const live = await this.store.findBySourceIp(ip);
      if (!live || live.getId() !== session.getId()) return;
      if (live.isExpiredAt(now)) return;

      try {
        await this.sync.upsertIdentitySession({
          id: live.getId(),
          identityUserId: live.getIdentityUserId(),
          radiusUsername: live.getUsername(),
          macAddress: live.getMacAddress(),
          ipAddress: ip,
          nasIp: live.getNasIp(),
          calledStationId: live.getCalledStationId(),
          authenticatedAt: live.getCreatedAt(),
          expiresAt: live.getExpiresAt(),
          groups: live.getGroups(),
        });
        this.logger.log({
          event: 'firewall.identity_session.replay.succeeded',
          message: 'identity session replayed to firewall',
          sessionId: live.getId(),
          username: live.getUsername(),
          sourceIp: ip,
        });
      } catch (error) {
        const message =
          error instanceof Error ? error.message : 'unknown error';
        this.logger.error({
          event: 'firewall.identity_session.replay.failed',
          message: 'failed to replay identity session to firewall',
          sessionId: live.getId(),
          sourceIp: ip,
          error: message,
        });
      }
    });
  }
}
