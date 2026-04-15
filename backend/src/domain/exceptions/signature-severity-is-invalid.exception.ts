export class SignatureSeverityIsInvalidException extends Error {
  constructor(severity: string) {
    super(
      `The signature severity "${severity}" is invalid. Allowed values are: SEVERITY_UNSPECIFIED, SEVERITY_INFO, SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL, UNRECOGNIZED.`,
    );

    this.name = "SignatureSeverityIsInvalidException";
  }
}
