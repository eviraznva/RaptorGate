import { Module } from '@nestjs/common';
import { ThrottlerModule } from '@nestjs/throttler';
import { RADIUS_AUTHENTICATOR_TOKEN } from '../application/ports/radius-authenticator.interface.js';
import { AuthenticateIdentityUseCase } from '../application/use-cases/authenticate-identity.use-case.js';
import { LogoutIdentityUseCase } from '../application/use-cases/logout-identity.use-case.js';
import { IDENTITY_SESSION_STORE_TOKEN } from '../domain/repositories/identity-session-store.js';
import { UdpRadiusAuthenticator } from '../infrastructure/adapters/udp-radius-authenticator.js';
import { IdentitySessionSweeperService } from '../infrastructure/identity/identity-session-sweeper.service.js';
import { InMemoryIdentitySessionStore } from '../infrastructure/identity/in-memory-identity-session.store.js';
import { IdentityController } from '../presentation/controllers/identity.controller.js';
import { IdentitySessionModule } from './identity-session.module.js';

// Modul identity (Issue 3): RADIUS auth, runtime session store, sweeper,
// publiczny kontroler portalu. Spina sie z IdentitySessionModule, ktory
// dostarcza klienta gRPC do firewalla (Issue 2).
@Module({
  imports: [IdentitySessionModule, ThrottlerModule],
  controllers: [IdentityController],
  providers: [
    AuthenticateIdentityUseCase,
    LogoutIdentityUseCase,
    IdentitySessionSweeperService,
    { provide: RADIUS_AUTHENTICATOR_TOKEN, useClass: UdpRadiusAuthenticator },
    {
      provide: IDENTITY_SESSION_STORE_TOKEN,
      useClass: InMemoryIdentitySessionStore,
    },
  ],
  exports: [IDENTITY_SESSION_STORE_TOKEN],
})
export class IdentityModule {}
