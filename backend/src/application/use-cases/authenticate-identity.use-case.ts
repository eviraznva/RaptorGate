import { randomUUID } from 'node:crypto';
import { Inject, Injectable, Logger } from '@nestjs/common';
import { IdentitySession } from '../../domain/entities/identity-session.entity.js';
import { AuthenticationMisconfiguredException } from '../../domain/exceptions/authentication-misconfigured.exception.js';
import { AuthenticationRejectedException } from '../../domain/exceptions/authentication-rejected.exception.js';
import { AuthenticationUnavailableException } from '../../domain/exceptions/authentication-unavailable.exception.js';
import {
  IDENTITY_SESSION_STORE_TOKEN,
  type IIdentitySessionStore,
} from '../../domain/repositories/identity-session-store.js';
import { IpAddress } from '../../domain/value-objects/ip-address.vo.js';
import {
  IDENTITY_SESSION_SYNC_SERVICE_TOKEN,
  type IIdentitySessionSyncService,
} from '../ports/identity-session-sync-service.interface.js';
import { AuthenticationEngineService } from '../services/authentication-engine.service.js';
import { AuthenticateIdentityDto } from '../dtos/authenticate-identity.dto.js';
import { AuthenticateIdentityResponseDto } from '../dtos/authenticate-identity-response.dto.js';

// Stale technicze dla pol IdentitySessionSyncPayload, ktore Issue 3 nie wypelnia.
// MAC: na MVP brak; Issue 7 moze go dolozyc z portalu/DHCP snoopingu.
// nas-ip / called-station-id: bierzemy z konfigu RADIUS, zeby firewall mial ten sam
// kontekst NAS co RADIUS provider.
const PLACEHOLDER_MAC = '00:00:00:00:00:00';

@Injectable()
export class AuthenticateIdentityUseCase {
  private readonly logger = new Logger(AuthenticateIdentityUseCase.name);

  constructor(
    @Inject(IDENTITY_SESSION_STORE_TOKEN)
    private readonly store: IIdentitySessionStore,
    @Inject(IDENTITY_SESSION_SYNC_SERVICE_TOKEN)
    private readonly sync: IIdentitySessionSyncService,
    @Inject(AuthenticationEngineService)
    private readonly authenticationEngine: AuthenticationEngineService,
  ) {}

  async execute(
    dto: AuthenticateIdentityDto,
  ): Promise<AuthenticateIdentityResponseDto> {
    // Walidacja sourceIp odbywa sie przez VO; zly IP od razu rzuca, zanim
    // dotkniemy RADIUS-a. Wymaganie Issue 3: sourceIp z requestu, nie z body.
    const sourceIp = IpAddress.create(dto.sourceIp);

    const result = await this.authenticationEngine.authenticate({
      flow: 'portal',
      username: dto.username,
      password: dto.password,
      sourceIp: sourceIp.getValue,
    });

    if (result.kind === 'reject') {
      this.logger.warn({
        event: 'identity.session.rejected',
        message: 'identity authentication rejected credentials, no session created',
        username: dto.username,
        sourceIp: sourceIp.getValue,
      });
      throw new AuthenticationRejectedException();
    }
    if (result.kind === 'timeout') {
      throw new AuthenticationUnavailableException('Authentication provider timeout');
    }
    if (result.kind === 'unavailable') {
      throw new AuthenticationUnavailableException(result.message);
    }
    if (result.kind === 'misconfigured' || result.kind === 'disabled') {
      throw new AuthenticationMisconfiguredException(result.message);
    }

    const now = new Date();
    const expiresAt = new Date(now.getTime() + result.sessionTtlSeconds * 1000);
    const sessionId = randomUUID();

    this.logger.log({
      event: 'identity.groups.resolved',
      message: 'identity groups resolved for new session',
      username: result.username,
      groupCount: result.groups.length,
    });

    const session = IdentitySession.create(
      sessionId,
      result.username,
      sourceIp,
      now,
      expiresAt,
      result.groups,
      result.nasIp,
      result.calledStationId,
    );

    await this.store.runExclusiveBySourceIp(sourceIp.getValue, async () => {
      await this.sync.upsertIdentitySession({
        id: sessionId,
        identityUserId: result.externalId,
        radiusUsername: result.username,
        macAddress: PLACEHOLDER_MAC,
        ipAddress: sourceIp.getValue,
        nasIp: result.nasIp,
        calledStationId: result.calledStationId,
        authenticatedAt: now,
        expiresAt,
        groups: session.getGroups(),
      });
      await this.store.upsert(session);
    });

    this.logger.log({
      event: 'identity.session.created',
      message: 'identity session created and synced to firewall',
      sessionId,
      username: result.username,
      sourceIp: sourceIp.getValue,
      expiresAt: expiresAt.toISOString(),
    });

    return {
      sessionId,
      username: result.username,
      sourceIp: sourceIp.getValue,
      authenticatedAt: now,
      expiresAt,
    };
  }
}
