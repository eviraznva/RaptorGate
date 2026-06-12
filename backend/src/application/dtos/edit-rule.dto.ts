import { SmtpMatchersDto } from '../../presentation/dtos/smtp-matchers.dto';
import { SshMatchersDto } from '../../presentation/dtos/ssh-matchers.dto';

export class EditRuleDto {
  id: string;
  name?: string;
  description?: string;
  zonePairId?: string;
  isActive?: boolean;
  content?: string;
  priority?: number;
  smtpMatchers?: SmtpMatchersDto;
  sshMatchers?: SshMatchersDto;
}
