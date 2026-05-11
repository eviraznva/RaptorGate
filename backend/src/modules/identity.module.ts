import { Module } from '@nestjs/common';
import { ThrottlerModule } from '@nestjs/throttler';
import { AuthenticateIdentityUseCase } from '../application/use-cases/authenticate-identity.use-case.js';
import { GetIdentitySessionUseCase } from '../application/use-cases/get-identity-session.use-case.js';
import { ListIdentitySessionsUseCase } from '../application/use-cases/list-identity-sessions.use-case.js';
import { LogoutIdentityUseCase } from '../application/use-cases/logout-identity.use-case.js';
import { RevokeIdentitySessionUseCase } from '../application/use-cases/revoke-identity-session.use-case.js';
import { IDENTITY_SESSION_STORE_TOKEN } from '../domain/repositories/identity-session-store.js';
import { IdentityGroupRefresherService } from '../infrastructure/identity/identity-group-refresher.service.js';
import { IdentitySessionReplayService } from '../infrastructure/identity/identity-session-replay.service.js';
import { IdentitySessionSweeperService } from '../infrastructure/identity/identity-session-sweeper.service.js';
import { FileStore } from '../infrastructure/persistence/json/file-store.js';
import { Mutex } from '../infrastructure/persistence/json/file-mutex.js';
import { JsonIdentitySessionStore } from '../infrastructure/persistence/repositories/json-identity-session.store.js';
import { IdentityController } from '../presentation/controllers/identity.controller.js';
import { IdentitySessionsController } from '../presentation/controllers/identity-sessions.controller.js';
import { AuthenticationEngineModule } from './authentication-engine.module.js';
import { IdentitySessionModule } from './identity-session.module.js';

// Modul identity (Issue 3, rozszerzony w Issue 4): RADIUS auth, LDAP groups,
// runtime session store, sweeper sesji, refresher grup, publiczny kontroler.
// Spina sie z IdentitySessionModule, ktory dostarcza klienta gRPC do firewalla.
@Module({
  imports: [AuthenticationEngineModule, IdentitySessionModule, ThrottlerModule],
  controllers: [IdentityController, IdentitySessionsController],
  providers: [
    AuthenticateIdentityUseCase,
    LogoutIdentityUseCase,
    GetIdentitySessionUseCase,
    ListIdentitySessionsUseCase,
    RevokeIdentitySessionUseCase,
    IdentitySessionSweeperService,
    IdentityGroupRefresherService,
    IdentitySessionReplayService,
    FileStore,
    Mutex,
    JsonIdentitySessionStore,
    {
      provide: IDENTITY_SESSION_STORE_TOKEN,
      useExisting: JsonIdentitySessionStore,
    },
  ],
  exports: [IDENTITY_SESSION_STORE_TOKEN],
})
export class IdentityModule {}
