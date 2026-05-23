// Port klienta RADIUS Access-Request (Issue 3, RFC 2865, PAP).
// Implementacja w infrastructure odpowiada za encoding pakietow,
// retransmisje i timeout. Use-case rozrozni 4 stany: accept/reject/timeout/error.

export interface RadiusAttributeResult {
  userGroups: string[];
  adminRole: string | null;
  accessDomain: string | null;
  panoramaAdminRole: string | null;
  panoramaAccessDomain: string | null;
  userDomain: string | null;
  rawDiagnostics: string[];
}

export type RadiusAuthResult =
  | { kind: 'accept'; groups: string[]; attributes?: RadiusAttributeResult; attemptedEndpoints?: string[] }
  | { kind: 'reject'; reason: string; attemptedEndpoints?: string[] }
  | { kind: 'timeout'; attemptedEndpoints?: string[] }
  | { kind: 'error'; message: string; attemptedEndpoints?: string[] };

export interface RadiusAuthServerOptions {
  name: string;
  host: string;
  port: number;
  secret: string;
  priority: number;
}

export interface RadiusAuthProfileOptions {
  authenticationProtocol: 'pap';
  timeoutMs: number;
  retries: number;
  nasIp: string;
  nasIdentifier: string;
  calledStationId: string | null;
  servers: RadiusAuthServerOptions[];
}

export interface RadiusAuthRequest {
  username: string;
  password: string;
  // sourceIp klienta — wedruje jako Calling-Station-Id (attr 31).
  callingStationId: string;
  profile: RadiusAuthProfileOptions;
}

export interface IRadiusAuthenticator {
  authenticate(request: RadiusAuthRequest): Promise<RadiusAuthResult>;
}

export const RADIUS_AUTHENTICATOR_TOKEN = Symbol('RADIUS_AUTHENTICATOR_TOKEN');
