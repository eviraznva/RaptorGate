import { SignatureSeverityIsInvalidException } from "../exceptions/signature-severity-is-invalid.exception.js";

export type SignatureSeverityType =
  | "SEVERITY_UNSPECIFIED"
  | "SEVERITY_INFO"
  | "SEVERITY_LOW"
  | "SEVERITY_MEDIUM"
  | "SEVERITY_HIGH"
  | "SEVERITY_CRITICAL"
  | "UNRECOGNIZED";

export class SignatureSeverity {
  private static readonly ALLOWED_VALUES: SignatureSeverityType[] = [
    "SEVERITY_UNSPECIFIED",
    "SEVERITY_INFO",
    "SEVERITY_LOW",
    "SEVERITY_MEDIUM",
    "SEVERITY_HIGH",
    "SEVERITY_CRITICAL",
    "UNRECOGNIZED",
  ];

  private readonly value: SignatureSeverityType;

  private constructor(severity: SignatureSeverityType) {
    this.value = severity;
  }

  public static create(severity: string): SignatureSeverity {
    if (!SignatureSeverity.isValidType(severity)) {
      throw new SignatureSeverityIsInvalidException(severity);
    }
    return new SignatureSeverity(severity as SignatureSeverityType);
  }

  private static isValidType(type: string): boolean {
    return SignatureSeverity.ALLOWED_VALUES.includes(
      type as SignatureSeverityType,
    );
  }

  public getValue(): SignatureSeverityType {
    return this.value;
  }
}
