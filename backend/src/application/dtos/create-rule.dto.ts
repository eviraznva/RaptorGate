import { SmtpMatchersDto } from '../../presentation/dtos/smtp-matchers.dto';

export class CreateRuleDto {
  name: string;
  description?: string;
  zonePairId: string;
  isActive: boolean;
  content: string;
  priority: number;
  accessToken: string;
  smtpMatchers: SmtpMatchersDto;
}
