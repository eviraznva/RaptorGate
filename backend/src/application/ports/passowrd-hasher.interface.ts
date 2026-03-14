export interface IPasswordHasher {
  hash(password: string): Promise<string>;
  compare(password: string, hashedPassword: string): Promise<boolean>;
}

export const PASSWORD_HASHER_TOKEN = Symbol('PASSWORD_HASHER_TOKEN');
