import { randomUUID } from 'node:crypto';
import { Inject, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { IdentitySession } from '../../domain/entities/identity-session.entity.js';
import { RadiusAccessRejectedException } from '../../domain/exceptions/radius-access-rejected.exception.js';
import { RadiusUnavailableException } from '../../domain/exceptions/radius-unavailable.exception.js';
import {
  IDENTITY_SESSION_STORE_TOKEN,
  type IIdentitySessionStore,
} from '../../domain/repositories/identity-session-store.js';
import { IpAddress } from '../../domain/value-objects/ip-address.vo.js';
import type { Env } from '../../shared/config/env.validation.js';
import {
  IDENTITY_SESSION_SYNC_SERVICE_TOKEN,
  type IIdentitySessionSyncService,
} from '../ports/identity-session-sync-service.interface.js';
import {
  RADIUS_AUTHENTICATOR_TOKEN,
  type IRadiusAuthenticator,
} from '../ports/radius-authenticator.interface.js';
import { AuthenticateIdentityDto } from '../dtos/authenticate-identity.dto.js';
import { AuthenticateIdentityResponseDto } from '../dtos/authenticate-identity-response.dto.js';

// Stale technicze dla pol IdentitySessionSyncPayload, ktore Issue 3 nie wypelnia.
// MAC: na MVP brak; Issue 7 lub Issue 4 moga go dolozyc.
// nas-ip / called-station-id: bierzemy z konfigu RADIUS, zeby firewall mial ten sam
// kontekst NAS co RADIUS provider.
const PLACEHOLDER_MAC = '00:00:00:00:00:00';

@Injectable()
export class AuthenticateIdentityUseCase {
  private readonly logger = new Logger(AuthenticateIdentityUseCase.name);

  constructor(
    @Inject(RADIUS_AUTHENTICATOR_TOKEN)
    private readonly radius: IRadiusAuthenticator,
    @Inject(IDENTITY_SESSION_STORE_TOKEN)
    private readonly store: IIdentitySessionStore,
    @Inject(IDENTITY_SESSION_SYNC_SERVICE_TOKEN)
    private readonly sync: IIdentitySessionSyncService,
    @Inject(ConfigService)
    private readonly configService: ConfigService<Env, true>,
  ) {}

  async execute(
    dto: AuthenticateIdentityDto,
  ): Promise<AuthenticateIdentityResponseDto> {
    // Walidacja sourceIp odbywa sie przez VO; zly IP od razu rzuca, zanim
    // dotkniemy RADIUS-a. Wymaganie Issue 3: sourceIp z requestu, nie z body.
    const sourceIp = IpAddress.create(dto.sourceIp);

    const result = await this.radius.authenticate({
      username: dto.username,
      password: dto.password,
      callingStationId: sourceIp.getValue,
    });

    if (result.kind === 'reject') {
      this.logger.warn({
        event: 'identity.session.rejected',
        message: 'RADIUS rejected credentials, no session created',
        username: dto.username,
        sourceIp: sourceIp.getValue,
      });
      throw new RadiusAccessRejectedException();
    }
    if (result.kind === 'timeout') {
      throw new RadiusUnavailableException('RADIUS timeout');
    }
    if (result.kind === 'error') {
      throw new RadiusUnavailableException(`RADIUS error: ${result.message}`);
    }

    const ttlSeconds = this.configService.get('IDENTITY_SESSION_TTL_SECONDS', {
      infer: true,
    });
    const nasIp = this.configService.get('RADIUS_NAS_IP', { infer: true });
    const nasIdentifier = this.configService.get('RADIUS_NAS_IDENTIFIER', {
      infer: true,
    });

    const now = new Date();
    const expiresAt = new Date(now.getTime() + ttlSeconds * 1000);
    const sessionId = randomUUID();

    const session = IdentitySession.create(
      sessionId,
      dto.username,
      sourceIp,
      now,
      expiresAt,
    );

    await this.store.runExclusiveBySourceIp(sourceIp.getValue, async () => {
      await this.sync.upsertIdentitySession({
        id: sessionId,
        // TODO(Issue 4): identityUserId zostanie zresolvowane z LDAP do realnego rekordu IdentityUser.
        identityUserId: dto.username,
        radiusUsername: dto.username,
        macAddress: PLACEHOLDER_MAC,
        ipAddress: sourceIp.getValue,
        nasIp,
        calledStationId: nasIdentifier,
        authenticatedAt: now,
        expiresAt,
      });
      await this.store.upsert(session);
    });

    this.logger.log({
      event: 'identity.session.created',
      message: 'identity session created and synced to firewall',
      sessionId,
      username: dto.username,
      sourceIp: sourceIp.getValue,
      expiresAt: expiresAt.toISOString(),
    });

    return {
      sessionId,
      username: dto.username,
      sourceIp: sourceIp.getValue,
      authenticatedAt: now,
      expiresAt,
    };
  }
}
