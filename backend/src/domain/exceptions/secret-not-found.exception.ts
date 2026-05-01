import { EntityNotFoundException } from './entity-not-found-exception.js';

export class SecretNotFoundException extends EntityNotFoundException {
  constructor(ref: string) {
    super('Secret', ref);
    this.name = 'SecretNotFoundException';
  }
}
