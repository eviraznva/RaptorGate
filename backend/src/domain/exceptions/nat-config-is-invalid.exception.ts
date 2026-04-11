export class NatConfigIsInvalidException extends Error {
  constructor(type: string, field: string, message?: string) {
    super(`NAT rule of type ${type} is invalid: ${field}. ${message || ''}`);
  }
}
