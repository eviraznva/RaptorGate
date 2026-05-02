import { Inject, Injectable } from '@nestjs/common';
import type {
  AuthenticationEngineResult,
  AuthenticationProviderRequest,
  AuthenticationProviderService,
  ResolvedAuthenticationProfile,
} from '../dtos/authentication-engine.dto.js';
import {
  USER_REPOSITORY_TOKEN,
  type IUserRepository,
} from '../../domain/repositories/user.repository.js';
import {
  PASSWORD_HASHER_TOKEN,
  type IPasswordHasher,
} from '../ports/passowrd-hasher.interface.js';
import { AuthenticationGroupResolverService } from './authentication-group-resolver.service.js';

const LOCAL_NAS_IP = '127.0.0.1';
const LOCAL_CALLED_STATION_ID = 'local';

@Injectable()
export class LocalAuthenticationProviderService implements AuthenticationProviderService {
  constructor(
    @Inject(USER_REPOSITORY_TOKEN)
    private readonly userRepository: IUserRepository,
    @Inject(PASSWORD_HASHER_TOKEN)
    private readonly passwordHasher: IPasswordHasher,
    @Inject(AuthenticationGroupResolverService)
    private readonly groupResolver: AuthenticationGroupResolverService,
  ) {}

  async authenticate(
    request: AuthenticationProviderRequest,
    resolved: ResolvedAuthenticationProfile,
  ): Promise<AuthenticationEngineResult> {
    const user = await this.userRepository.findByUsername(request.username);
    if (!user) {
      return {
        kind: 'reject',
        provider: 'local',
        reason: 'local user not found',
        profileId: resolved.authenticationProfile.getId(),
      };
    }

    const valid = await this.passwordHasher.compare(
      request.password,
      user.getPasswordHash(),
    );
    if (!valid) {
      return {
        kind: 'reject',
        provider: 'local',
        reason: 'local password rejected',
        profileId: resolved.authenticationProfile.getId(),
      };
    }

    const groups = await this.groupResolver.resolve(
      resolved,
      user.getUsername(),
      [],
    );

    return {
      kind: 'accept',
      provider: 'local',
      username: user.getUsername(),
      groups: groups.groups,
      groupSource: groups.source,
      externalId: groups.externalId,
      sessionTtlSeconds: resolved.authenticationProfile.getSessionTtlSeconds(),
      nasIp: LOCAL_NAS_IP,
      calledStationId: LOCAL_CALLED_STATION_ID,
      profileId: resolved.authenticationProfile.getId(),
    };
  }
}
