import { Module } from '@nestjs/common';
import { LDAP_AUTHENTICATOR_TOKEN } from '../application/ports/ldap-authenticator.interface.js';
import { LDAP_DIRECTORY_TOKEN } from '../application/ports/ldap-directory.interface.js';
import { PASSWORD_HASHER_TOKEN } from '../application/ports/passowrd-hasher.interface.js';
import { RADIUS_AUTHENTICATOR_TOKEN } from '../application/ports/radius-authenticator.interface.js';
import { AuthenticationEngineService } from '../application/services/authentication-engine.service.js';
import { AuthenticationGroupResolverService } from '../application/services/authentication-group-resolver.service.js';
import { AuthenticationProfileResolverService } from '../application/services/authentication-profile-resolver.service.js';
import { LdapAuthenticationProviderService } from '../application/services/ldap-authentication-provider.service.js';
import { LocalAuthenticationProviderService } from '../application/services/local-authentication-provider.service.js';
import { RadiusAuthenticationProviderService } from '../application/services/radius-authentication-provider.service.js';
import { USER_REPOSITORY_TOKEN } from '../domain/repositories/user.repository.js';
import { BcryptPasswordHasher } from '../infrastructure/adapters/bcrypt-password-hasher.js';
import { TcpLdapAuthenticatorAdapter } from '../infrastructure/adapters/ldap/tcp-ldap-authenticator.js';
import { TcpLdapDirectoryAdapter } from '../infrastructure/adapters/ldap/tcp-ldap-directory.js';
import { UdpRadiusAuthenticator } from '../infrastructure/adapters/udp-radius-authenticator.js';
import { Mutex } from '../infrastructure/persistence/json/file-mutex.js';
import { FileStore } from '../infrastructure/persistence/json/file-store.js';
import { JsonUserRepository } from '../infrastructure/persistence/repositories/json-user.repository.js';
import { IdentityConfigStoreModule } from './identity-config-store.module.js';
import { SecretModule } from './secret.module.js';

@Module({
  imports: [IdentityConfigStoreModule, SecretModule],
  providers: [
    AuthenticationEngineService,
    AuthenticationGroupResolverService,
    AuthenticationProfileResolverService,
    RadiusAuthenticationProviderService,
    LdapAuthenticationProviderService,
    LocalAuthenticationProviderService,
    FileStore,
    Mutex,
    { provide: RADIUS_AUTHENTICATOR_TOKEN, useClass: UdpRadiusAuthenticator },
    { provide: LDAP_DIRECTORY_TOKEN, useClass: TcpLdapDirectoryAdapter },
    { provide: LDAP_AUTHENTICATOR_TOKEN, useClass: TcpLdapAuthenticatorAdapter },
    { provide: PASSWORD_HASHER_TOKEN, useClass: BcryptPasswordHasher },
    { provide: USER_REPOSITORY_TOKEN, useClass: JsonUserRepository },
  ],
  exports: [
    AuthenticationEngineService,
    AuthenticationGroupResolverService,
    AuthenticationProfileResolverService,
  ],
})
export class AuthenticationEngineModule {}
