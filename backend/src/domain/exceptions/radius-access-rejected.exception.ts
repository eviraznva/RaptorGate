// RADIUS odrzucil Access-Request (Access-Reject). Bledne dane lub brak konta.
export class RadiusAccessRejectedException extends Error {
  constructor(reason = 'Invalid username or password.') {
    super(reason);
    this.name = 'RadiusAccessRejectedException';
  }
}
