import { Inject, Injectable } from '@nestjs/common';
import type { ISslBypassRepository } from '../../domain/repositories/ssl-bypass.repository.js';
import { SSL_BYPASS_REPOSITORY_TOKEN } from '../../domain/repositories/ssl-bypass.repository.js';
import {
  mapSslBypassDomain,
  type GetSslBypassDomainsResponseDto,
} from '../dtos/ssl-bypass-domain.dto.js';

@Injectable()
export class GetSslBypassDomainsUseCase {
  constructor(
    @Inject(SSL_BYPASS_REPOSITORY_TOKEN)
    private readonly sslBypassRepository: ISslBypassRepository,
  ) {}

  async execute(): Promise<GetSslBypassDomainsResponseDto> {
    const entries = await this.sslBypassRepository.findAll();

    return {
      bypassDomains: entries.map((entry) => mapSslBypassDomain(entry)),
    };
  }
}
