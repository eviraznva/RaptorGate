export class IpsSignatureConfigIsInvalidException extends Error {
  constructor(message: string) {
    super(message);

    this.name = "IpsSignatureConfigIsInvalidException";
  }
}
