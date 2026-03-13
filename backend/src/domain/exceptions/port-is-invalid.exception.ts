export class PortIsInvalidException extends Error {
  constructor(port: number) {
    super(
      `The port number "${port}" is invalid. It must be an integer between 1 and 65535.`,
    );

    this.name = 'PortIsInvalidException';
  }
}
