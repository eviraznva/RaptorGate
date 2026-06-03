import type { IdentityAuthenticationProvider, IdentityGroupSource } from '../../domain/entities/identity-authentication-profile.entity.js';
import type { IdentityAuthenticationProfile } from '../../domain/entities/identity-authentication-profile.entity.js';
import type { LdapServerProfile } from '../../domain/entities/ldap-server-profile.entity.js';
import type { RadiusServerProfile } from '../../domain/entities/radius-server-profile.entity.js';
import type { RadiusAttributeResult } from '../ports/radius-authenticator.interface.js';

export type AuthenticationFlow = 'portal' | 'admin';

export interface AuthenticationEngineRequest {
  flow: AuthenticationFlow;
  username: string;
  password: string;
  sourceIp?: string;
}

export interface ResolvedAuthenticationProfile {
  kind: 'resolved';
  flow: AuthenticationFlow;
  authenticationProfile: IdentityAuthenticationProfile;
  radiusProfile: RadiusServerProfile | null;
  ldapProfile: LdapServerProfile | null;
}

export type AuthenticationProfileResolution =
  | ResolvedAuthenticationProfile
  | { kind: 'disabled'; message: string }
  | { kind: 'misconfigured'; message: string; profileId?: string };

export type AuthenticationEngineAcceptResult = {
  kind: 'accept';
  provider: IdentityAuthenticationProvider;
  username: string;
  groups: string[];
  groupSource: IdentityGroupSource;
  externalId: string;
  sessionTtlSeconds: number;
  nasIp: string;
  calledStationId: string;
  profileId: string;
  radiusAttributes?: RadiusAttributeResult;
};

export type AuthenticationEngineResult =
  | AuthenticationEngineAcceptResult
  | {
      kind: 'reject';
      provider?: IdentityAuthenticationProvider;
      reason: string;
      profileId?: string;
    }
  | {
      kind: 'timeout';
      provider?: IdentityAuthenticationProvider;
      message: string;
      profileId?: string;
    }
  | {
      kind: 'unavailable';
      provider?: IdentityAuthenticationProvider;
      message: string;
      profileId?: string;
    }
  | {
      kind: 'misconfigured';
      message: string;
      profileId?: string;
    }
  | {
      kind: 'disabled';
      message: string;
    };

export interface AuthenticationProviderRequest {
  username: string;
  password: string;
  sourceIp?: string;
}

export interface AuthenticationProviderService {
  authenticate(
    request: AuthenticationProviderRequest,
    resolved: ResolvedAuthenticationProfile,
  ): Promise<AuthenticationEngineResult>;
}

export interface AuthenticationGroupResolution {
  groups: string[];
  externalId: string;
  source: IdentityGroupSource;
  diagnostic: 'ok' | 'not-found' | 'disabled' | 'error' | 'skipped';
  error?: string;
}
