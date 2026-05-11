export type SmtpMatchAction = 'allow' | 'deny';

export interface SmtpMatch {
  regex: string;
  onMatch: SmtpMatchAction;
}

export interface SmtpMatchers {
  sender: SmtpMatch[];
  recipient: SmtpMatch[];
  message: SmtpMatch[];
}

export interface Rule {
  id: string;
  name: string;
  priority: number;
  content: string;
  description: string;
  isActive: boolean;
  zonePairId: string;
  createdAt: string;
  updatedAt: string;
  createdBy: string;
  smtpMatchers: SmtpMatchers;
}
