export const RefreshTokenIsInvalidException = class extends Error {
  constructor() {
    super('Refresh token is invalid or expired.');

    this.name = 'RefreshTokenIsInvalidException';
  }
};
