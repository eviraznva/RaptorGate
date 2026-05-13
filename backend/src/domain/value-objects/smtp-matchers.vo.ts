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

export function createEmptySmtpMatchers(): SmtpMatchers {
  return {
    sender: [],
    recipient: [],
    message: [],
  };
}
