import { IPasswordHasher } from 'src/application/ports/passowrd-hasher.interface';
import { Env } from 'src/shared/config/env.validation';
import { ConfigService } from '@nestjs/config';
import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';

@Injectable()
export class BcryptPasswordHasher implements IPasswordHasher {
  constructor(private readonly configService: ConfigService<Env, true>) {}

  async hash(password: string): Promise<string> {
    const saltRounds =
      this.configService.getOrThrow<number>('BCRYPT_SALT_ROUNDS');

    return await bcrypt.hash(password, saltRounds);
  }

  async compare(password: string, hashedPassword: string): Promise<boolean> {
    return await bcrypt.compare(password, hashedPassword);
  }
}
