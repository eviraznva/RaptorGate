export class NatTypeIsInvalidException extends Error {
  constructor(natType: string) {
    super(
      `The NAT type "${natType}" is invalid. Valid values are "Open", "Moderate", and "Strict".`,
    );

    this.name = 'NatTypeIsInvalidException';
  }
}
