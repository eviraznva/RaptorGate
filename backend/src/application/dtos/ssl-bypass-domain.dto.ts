import { SslBypassEntry } from '../../domain/entities/ssl-bypass-entry.entity.js';

export interface SslBypassDomainDto {
  id: string;
  domain: string;
  reason: string;
  isActive: boolean;
  createdAt: string;
}

export interface GetSslBypassDomainsResponseDto {
  bypassDomains: SslBypassDomainDto[];
}

export interface CreateSslBypassDomainDto {
  domain: string;
  reason?: string;
  accessToken: string;
}

export interface CreateSslBypassDomainResponseDto {
  bypassDomain: SslBypassDomainDto;
}

export interface DeleteSslBypassDomainDto {
  id: string;
  accessToken: string;
}

export function mapSslBypassDomain(entry: SslBypassEntry): SslBypassDomainDto {
  return {
    id: entry.getId(),
    domain: entry.getDomain(),
    reason: entry.getReason(),
    isActive: entry.getIsActive(),
    createdAt: entry.getCreatedAt().toISOString(),
  };
}
