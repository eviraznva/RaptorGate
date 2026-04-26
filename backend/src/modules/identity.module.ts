import { Module } from '@nestjs/common';
import { ThrottlerModule } from '@nestjs/throttler';
import { LDAP_DIRECTORY_TOKEN } from '../application/ports/ldap-directory.interface.js';
import { LDAP_GROUP_CACHE_TOKEN } from '../application/ports/ldap-group-cache.interface.js';
import { RADIUS_AUTHENTICATOR_TOKEN } from '../application/ports/radius-authenticator.interface.js';
import { IdentityGroupResolverService } from '../application/services/identity-group-resolver.service.js';
import { AuthenticateIdentityUseCase } from '../application/use-cases/authenticate-identity.use-case.js';
import { GetIdentitySessionUseCase } from '../application/use-cases/get-identity-session.use-case.js';
import { LogoutIdentityUseCase } from '../application/use-cases/logout-identity.use-case.js';
import { IDENTITY_SESSION_STORE_TOKEN } from '../domain/repositories/identity-session-store.js';
import { TcpLdapDirectoryAdapter } from '../infrastructure/adapters/ldap/tcp-ldap-directory.js';
import { UdpRadiusAuthenticator } from '../infrastructure/adapters/udp-radius-authenticator.js';
import { IdentityGroupRefresherService } from '../infrastructure/identity/identity-group-refresher.service.js';
import { IdentitySessionSweeperService } from '../infrastructure/identity/identity-session-sweeper.service.js';
import { InMemoryIdentitySessionStore } from '../infrastructure/identity/in-memory-identity-session.store.js';
import { InMemoryLdapGroupCache } from '../infrastructure/identity/in-memory-ldap-group-cache.js';
import { IdentityController } from '../presentation/controllers/identity.controller.js';
import { IdentitySessionModule } from './identity-session.module.js';

// Modul identity (Issue 3, rozszerzony w Issue 4): RADIUS auth, LDAP groups,
// runtime session store, sweeper sesji, refresher grup, publiczny kontroler.
// Spina sie z IdentitySessionModule, ktory dostarcza klienta gRPC do firewalla.
@Module({
  imports: [IdentitySessionModule, ThrottlerModule],
  controllers: [IdentityController],
  providers: [
    AuthenticateIdentityUseCase,
    LogoutIdentityUseCase,
    GetIdentitySessionUseCase,
    IdentitySessionSweeperService,
    IdentityGroupResolverService,
    IdentityGroupRefresherService,
    { provide: RADIUS_AUTHENTICATOR_TOKEN, useClass: UdpRadiusAuthenticator },
    { provide: LDAP_DIRECTORY_TOKEN, useClass: TcpLdapDirectoryAdapter },
    { provide: LDAP_GROUP_CACHE_TOKEN, useClass: InMemoryLdapGroupCache },
    {
      provide: IDENTITY_SESSION_STORE_TOKEN,
      useClass: InMemoryIdentitySessionStore,
    },
  ],
  exports: [IDENTITY_SESSION_STORE_TOKEN],
})
export class IdentityModule {}
