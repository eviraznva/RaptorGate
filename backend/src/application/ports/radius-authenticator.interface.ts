// Port klienta RADIUS Access-Request (Issue 3, RFC 2865, PAP).
// Implementacja w infrastructure odpowiada za encoding pakietow,
// retransmisje i timeout. Use-case rozrozni 4 stany: accept/reject/timeout/error.

export type RadiusAuthResult =
  | { kind: 'accept' }
  | { kind: 'reject'; reason: string }
  | { kind: 'timeout' }
  | { kind: 'error'; message: string };

export interface RadiusAuthRequest {
  username: string;
  password: string;
  // sourceIp klienta — wedruje jako Calling-Station-Id (attr 31).
  callingStationId: string;
}

export interface IRadiusAuthenticator {
  authenticate(request: RadiusAuthRequest): Promise<RadiusAuthResult>;
}

export const RADIUS_AUTHENTICATOR_TOKEN = Symbol('RADIUS_AUTHENTICATOR_TOKEN');
