import { UserSourceIsInvalidException } from '../exceptions/user-source-is-invalid.exception';

export type UserSourceType = 'radius' | 'active_directory' | 'local';

export class UserSource {
  private static readonly ALLOWED_VALUES: UserSourceType[] = [
    'radius',
    'active_directory',
    'local',
  ];

  private readonly value: UserSourceType;

  private constructor(sourceType: UserSourceType) {
    this.value = sourceType;
  }

  public static create(sourceType: UserSourceType): UserSource {
    if (!this.isValidType(sourceType)) {
      throw new UserSourceIsInvalidException(sourceType);
    }

    return new UserSource(sourceType);
  }

  private static isValidType(type: string): boolean {
    return UserSource.ALLOWED_VALUES.includes(type as UserSourceType);
  }

  public getValue(): UserSourceType {
    return this.value;
  }

  public isRaiuds(): boolean {
    return this.value === 'radius';
  }

  public isActiveDirectory(): boolean {
    return this.value === 'active_directory';
  }

  public isLocal(): boolean {
    return this.value === 'local';
  }
}
