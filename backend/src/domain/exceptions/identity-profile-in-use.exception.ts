export class IdentityProfileInUseException extends Error {
  constructor(
    public readonly profileType: string,
    public readonly profileId: string,
    public readonly usedBy: string,
  ) {
    super(`${profileType} profile "${profileId}" is used by ${usedBy}.`);
    this.name = 'IdentityProfileInUseException';
  }
}
