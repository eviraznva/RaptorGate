export class CreateBlacklistEntryDto {
  domain: string[];
  reason: string;
  isActive: boolean;
  accessToken: string;
}
