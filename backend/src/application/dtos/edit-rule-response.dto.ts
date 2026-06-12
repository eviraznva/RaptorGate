import { SmtpMatchers } from '../../domain/value-objects/smtp-matchers.vo.js';
import { SshMatchers } from '../../domain/value-objects/ssh-matchers.vo.js';

export class EditRuleResponseDto {
  id: string;
  name: string;
  description: string | null;
  zonePairId: string;
  isActive: boolean;
  content: string;
  priority: number;
  createdAt: Date;
  updatedAt: Date;
  createdBy: string;
  smtpMatchers: SmtpMatchers;
  sshMatchers: SshMatchers;
}
