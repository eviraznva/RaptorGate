export type IdentityProviderTestResult =
  | 'accept'
  | 'reject'
  | 'timeout'
  | 'ok'
  | 'not_found'
  | 'disabled'
  | 'error';

export interface IdentityProviderTestResponseDto {
  result: IdentityProviderTestResult;
  latencyMs: number;
  message: string;
  groups?: string[];
  userDn?: string;
}
