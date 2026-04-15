export class IpsActionIsInvalidException extends Error {
  constructor(action: string) {
    super(
      `The IPS action "${action}" is invalid. Allowed values are: IPS_ACTION_UNSPECIFIED, IPS_ACTION_ALERT, IPS_ACTION_BLOCK, UNRECOGNIZED.`,
    );

    this.name = "IpsActionIsInvalidException";
  }
}
