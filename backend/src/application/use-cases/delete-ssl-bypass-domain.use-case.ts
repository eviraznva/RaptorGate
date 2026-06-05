import { Inject, Injectable, Logger } from '@nestjs/common';
import { AccessTokenIsInvalidException } from '../../domain/exceptions/acces-token-is-invalid.exception.js';
import { EntityNotFoundException } from '../../domain/exceptions/entity-not-found-exception.js';
import type { IConfigSnapshotRepository } from '../../domain/repositories/config-snapshot.repository.js';
import { CONFIG_SNAPSHOT_REPOSITORY_TOKEN } from '../../domain/repositories/config-snapshot.repository.js';
import type { ISslBypassRepository } from '../../domain/repositories/ssl-bypass.repository.js';
import { SSL_BYPASS_REPOSITORY_TOKEN } from '../../domain/repositories/ssl-bypass.repository.js';
import type { DeleteSslBypassDomainDto } from '../dtos/ssl-bypass-domain.dto.js';
import type { IConfigSnapshotPushService } from '../ports/config-snapshot-push-service.interface.js';
import { CONFIG_SNAPSHOT_PUSH_SERVICE_TOKEN } from '../ports/config-snapshot-push-service.interface.js';
import type { ITokenService } from '../ports/token-service.interface.js';
import { TOKEN_SERVICE_TOKEN } from '../ports/token-service.interface.js';
import { pushSslBypassSnapshot } from './ssl-bypass-snapshot.js';

@Injectable()
export class DeleteSslBypassDomainUseCase {
  private readonly logger = new Logger(DeleteSslBypassDomainUseCase.name);

  constructor(
    @Inject(SSL_BYPASS_REPOSITORY_TOKEN)
    private readonly sslBypassRepository: ISslBypassRepository,
    @Inject(CONFIG_SNAPSHOT_REPOSITORY_TOKEN)
    private readonly configSnapshotRepository: IConfigSnapshotRepository,
    @Inject(CONFIG_SNAPSHOT_PUSH_SERVICE_TOKEN)
    private readonly configSnapshotPushService: IConfigSnapshotPushService,
    @Inject(TOKEN_SERVICE_TOKEN) private readonly tokenService: ITokenService,
  ) {}

  async execute(dto: DeleteSslBypassDomainDto): Promise<void> {
    const claims = this.tokenService.decodeAccessToken(dto.accessToken);
    if (!claims) throw new AccessTokenIsInvalidException();

    const existing = await this.sslBypassRepository.findById(dto.id);
    if (!existing) throw new EntityNotFoundException('TLS bypass domain', dto.id);

    await this.sslBypassRepository.delete(dto.id);
    await pushSslBypassSnapshot(
      this.configSnapshotRepository,
      this.configSnapshotPushService,
      await this.sslBypassRepository.findAll(),
      claims.sub,
    );

    this.logger.log({
      event: 'ssl_bypass.delete.succeeded',
      message: 'TLS bypass domain deleted',
      actorId: claims.sub,
      bypassDomainId: existing.getId(),
      domain: existing.getDomain(),
    });
  }
}
