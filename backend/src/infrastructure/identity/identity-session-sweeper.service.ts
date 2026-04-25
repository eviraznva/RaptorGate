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
import {
  IDENTITY_SESSION_STORE_TOKEN,
  type IIdentitySessionStore,
} from '../../domain/repositories/identity-session-store.js';
import type { Env } from '../../shared/config/env.validation.js';

// Sweeper wygasajacych sesji identity (ADR 0003): backend jest wlascicielem
// expire i wysyla Revoke do firewalla. Firewall dodatkowo enforce'uje
// expires_at per pakiet (Issue 5), wiec drobne opoznienie sweepera nie psuje
// bezpieczenstwa.
@Injectable()
export class IdentitySessionSweeperService
  implements OnModuleInit, OnModuleDestroy
{
  private readonly logger = new Logger(IdentitySessionSweeperService.name);
  private timer: NodeJS.Timeout | null = null;
  private running = false;

  constructor(
    @Inject(ConfigService)
    private readonly configService: ConfigService<Env, true>,
    @Inject(IDENTITY_SESSION_STORE_TOKEN)
    private readonly store: IIdentitySessionStore,
    @Inject(IDENTITY_SESSION_SYNC_SERVICE_TOKEN)
    private readonly sync: IIdentitySessionSyncService,
  ) {}

  onModuleInit(): void {
    const intervalMs = this.configService.get(
      'IDENTITY_SESSION_SWEEP_INTERVAL_MS',
      { infer: true },
    );
    this.timer = setInterval(() => {
      void this.sweepOnce();
    }, intervalMs);
    // Nie blokujemy zamkniecia procesu na timerze sweepera.
    this.timer.unref?.();
  }

  onModuleDestroy(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  // Wystawione publicznie dla testow i Issue 8 (manualny trigger z UI).
  async sweepOnce(now: Date = new Date()): Promise<void> {
    if (this.running) return;
    this.running = true;
    try {
      const expired = await this.store.peekExpired(now);
      for (const session of expired) {
        const ip = session.getSourceIp().getValue;
        await this.store.runExclusiveBySourceIp(ip, async () => {
          const current = await this.store.findBySourceIp(ip);
          if (!current || current.getId() !== session.getId()) return;
          if (!current.isExpiredAt(now)) return;

          try {
            await this.sync.revokeIdentitySession(ip);
            await this.store.removeBySourceIp(ip);
            this.logger.log({
              event: 'identity.session.expired',
              message: 'expired identity session swept and revoked on firewall',
              sessionId: current.getId(),
              username: current.getUsername(),
              sourceIp: ip,
            });
          } catch (error) {
            const message =
              error instanceof Error ? error.message : 'unknown error';
            this.logger.error({
              event: 'identity.session.expire_sync_failed',
              message: 'failed to revoke expired session on firewall',
              sessionId: current.getId(),
              sourceIp: ip,
              error: message,
            });
          }
        });
      }
    } finally {
      this.running = false;
    }
  }
}
