// RADIUS niedostepny: timeout, blad sieci albo niewazna odpowiedz.
// Mapowane na 503 Service Unavailable na warstwie HTTP.
export class RadiusUnavailableException extends Error {
  constructor(message = 'RADIUS server is unavailable.') {
    super(message);
    this.name = 'RadiusUnavailableException';
  }
}
