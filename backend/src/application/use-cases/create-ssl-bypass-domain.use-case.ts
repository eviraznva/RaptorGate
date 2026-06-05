import { randomUUID } from 'node:crypto';
import { BadRequestException, Inject, Injectable, Logger } from '@nestjs/common';
import { SslBypassEntry } from '../../domain/entities/ssl-bypass-entry.entity.js';
import { AccessTokenIsInvalidException } from '../../domain/exceptions/acces-token-is-invalid.exception.js';
import type { IConfigSnapshotRepository } from '../../domain/repositories/config-snapshot.repository.js';
import { CONFIG_SNAPSHOT_REPOSITORY_TOKEN } from '../../domain/repositories/config-snapshot.repository.js';
import type { ISslBypassRepository } from '../../domain/repositories/ssl-bypass.repository.js';
import { SSL_BYPASS_REPOSITORY_TOKEN } from '../../domain/repositories/ssl-bypass.repository.js';
import { DomainName } from '../../domain/value-objects/domain-name.vo.js';
import {
  mapSslBypassDomain,
  type CreateSslBypassDomainDto,
  type CreateSslBypassDomainResponseDto,
} from '../dtos/ssl-bypass-domain.dto.js';
import type { IConfigSnapshotPushService } from '../ports/config-snapshot-push-service.interface.js';
import { CONFIG_SNAPSHOT_PUSH_SERVICE_TOKEN } from '../ports/config-snapshot-push-service.interface.js';
import type { ITokenService } from '../ports/token-service.interface.js';
import { TOKEN_SERVICE_TOKEN } from '../ports/token-service.interface.js';
import { pushSslBypassSnapshot } from './ssl-bypass-snapshot.js';

@Injectable()
export class CreateSslBypassDomainUseCase {
  private readonly logger = new Logger(CreateSslBypassDomainUseCase.name);

  constructor(
    @Inject(SSL_BYPASS_REPOSITORY_TOKEN)
    private readonly sslBypassRepository: ISslBypassRepository,
    @Inject(CONFIG_SNAPSHOT_REPOSITORY_TOKEN)
    private readonly configSnapshotRepository: IConfigSnapshotRepository,
    @Inject(CONFIG_SNAPSHOT_PUSH_SERVICE_TOKEN)
    private readonly configSnapshotPushService: IConfigSnapshotPushService,
    @Inject(TOKEN_SERVICE_TOKEN) private readonly tokenService: ITokenService,
  ) {}

  async execute(
    dto: CreateSslBypassDomainDto,
  ): Promise<CreateSslBypassDomainResponseDto> {
    const claims = this.tokenService.decodeAccessToken(dto.accessToken);
    if (!claims) throw new AccessTokenIsInvalidException();

    const domain = this.normalizeDomain(dto.domain);
    const reason = this.normalizeReason(dto.reason);
    const existing = await this.sslBypassRepository.findAll();
    if (existing.some((entry) => entry.getDomain().toLowerCase() === domain)) {
      throw new BadRequestException('TLS bypass domain already exists');
    }

    const entry = SslBypassEntry.create(
      randomUUID(),
      domain,
      reason,
      true,
      new Date(),
    );

    await this.sslBypassRepository.save(entry, claims.sub);
    await pushSslBypassSnapshot(
      this.configSnapshotRepository,
      this.configSnapshotPushService,
      await this.sslBypassRepository.findAll(),
      claims.sub,
    );

    this.logger.log({
      event: 'ssl_bypass.create.succeeded',
      message: 'TLS bypass domain created',
      actorId: claims.sub,
      bypassDomainId: entry.getId(),
      domain: entry.getDomain(),
    });

    return { bypassDomain: mapSslBypassDomain(entry) };
  }

  private normalizeDomain(domain: string): string {
    const normalized = domain.trim().toLowerCase();
    DomainName.create(normalized);
    return normalized;
  }

  private normalizeReason(reason?: string): string {
    const normalized = reason?.trim();
    return normalized && normalized.length > 0
      ? normalized
      : 'Manual TLS inspection bypass';
  }
}
