// import {
//   IRefreshTokenRepository,
//   RefreshTokenRecord,
// } from 'src/domain/repositories/refresh-token.repository';
// import { TokenFileGateway } from '../security/token-file-gateway';
// import { Inject, Injectable } from '@nestjs/common';
// import { Mutex } from '../json/file-mutex';

// @Injectable()
// export class RefreshTokenRepository implements IRefreshTokenRepository {
//   constructor(
//     @Inject(Mutex) private readonly mutex: Mutex,
//     private readonly gateway: TokenFileGateway,
//   ) {}

//   async set(record: RefreshTokenRecord): Promise<void> {
//     await this.mutex.runExclusive(async () => {
//       const payload = await this.gateway.readTokensPayload();

//       const row = {
//         userId: record.userId,
//         token: record.token,
//         expiresAt: record.expiresAt ? record.expiresAt.toISOString() : null,
//       };

//       const index = payload.tokens.findIndex((t) => t.userId === record.userId);
//       if (index >= 0) {
//         payload.tokens[index] = row;
//       } else {
//         payload.tokens.push(row);
//       }

//       await this.gateway.writeTokensPayload(payload);
//     });
//   }

//   async getByUserId(userId: string): Promise<RefreshTokenRecord | null> {
//     const payload = await this.gateway.readTokensPayload();

//     const row = payload.tokens.find((t) => t.userId === userId);
//     if (!row) return null;

//     return {
//       userId: row.userId,
//       token: row.token,
//       expiresAt: row.expiresAt ? new Date(row.expiresAt) : null,
//     };
//   }

//   async clearByUserId(userId: string): Promise<void> {
//     await this.mutex.runExclusive(async () => {
//       const payload = await this.gateway.readTokensPayload();
//       payload.tokens = payload.tokens.filter((t) => t.userId !== userId);

//       await this.gateway.writeTokensPayload(payload);
//     });
//   }
// }
