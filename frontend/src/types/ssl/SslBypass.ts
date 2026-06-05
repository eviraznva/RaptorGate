export interface SslBypassDomain {
  id: string;
  domain: string;
  reason: string;
  isActive: boolean;
  createdAt: string;
}

export type SslBypassDomainsPayload = {
  bypassDomains: SslBypassDomain[];
};

export type CreateSslBypassDomainPayload = {
  bypassDomain: SslBypassDomain;
};

export interface CreateSslBypassDomainRequest {
  domain: string;
  reason?: string;
}
