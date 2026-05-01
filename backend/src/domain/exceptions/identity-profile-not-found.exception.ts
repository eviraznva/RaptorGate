import { EntityNotFoundException } from './entity-not-found-exception.js';

export class IdentityProfileNotFoundException extends EntityNotFoundException {
  constructor(
    public readonly profileType: string,
    public readonly profileId: string,
  ) {
    super(`${profileType} profile`, profileId);
    this.name = 'IdentityProfileNotFoundException';
  }
}
