import { SecretValue } from '../../domain/value-objects/secret-value.vo.js';

export interface ISecretResolverService {
  resolve(ref: string): Promise<SecretValue>;
}

export const SECRET_RESOLVER_SERVICE_TOKEN = Symbol(
  'SECRET_RESOLVER_SERVICE_TOKEN',
);
