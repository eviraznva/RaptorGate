import { IpsActionIsInvalidException } from "../exceptions/ips-action-is-invalid.exception.js";

export type IpsActionType =
  | "IPS_ACTION_UNSPECIFIED"
  | "IPS_ACTION_ALERT"
  | "IPS_ACTION_BLOCK"
  | "UNRECOGNIZED";

export class IpsAction {
  private static readonly ALLOWED_VALUES: IpsActionType[] = [
    "IPS_ACTION_UNSPECIFIED",
    "IPS_ACTION_ALERT",
    "IPS_ACTION_BLOCK",
    "UNRECOGNIZED",
  ];

  private readonly value: IpsActionType;

  private constructor(action: IpsActionType) {
    this.value = action;
  }

  public static create(action: string): IpsAction {
    if (!IpsAction.isValidType(action)) {
      throw new IpsActionIsInvalidException(action);
    }

    return new IpsAction(action as IpsActionType);
  }

  private static isValidType(type: string): boolean {
    return IpsAction.ALLOWED_VALUES.includes(type as IpsActionType);
  }

  public getValue(): IpsActionType {
    return this.value;
  }
}
