export class IpsPatternEncodingIsInvalidException extends Error {
  constructor(patternEncoding: string) {
    super(`IPS pattern encoding '${patternEncoding}' is invalid`);

    this.name = "IpsPatternEncodingIsInvalidException";
  }
}
