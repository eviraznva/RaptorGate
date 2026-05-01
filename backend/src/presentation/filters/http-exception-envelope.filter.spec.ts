import { HttpStatus } from '@nestjs/common';
import { AuthenticationMisconfiguredException } from '../../domain/exceptions/authentication-misconfigured.exception.js';
import { AuthenticationUnavailableException } from '../../domain/exceptions/authentication-unavailable.exception.js';
import { HttpExceptionEnvelopeFilter } from './http-exception-envelope.filter.js';

describe('HttpExceptionEnvelopeFilter authentication mapping', () => {
  function map(exception: Error) {
    return (
      new HttpExceptionEnvelopeFilter() as unknown as {
        mapDomainToHttpException(exception: unknown): { getStatus(): number } | null;
      }
    ).mapDomainToHttpException(exception);
  }

  it('maps unavailable providers to 503', () => {
    expect(
      map(new AuthenticationUnavailableException('RADIUS timeout'))?.getStatus(),
    ).toBe(HttpStatus.SERVICE_UNAVAILABLE);
  });

  it('maps authentication misconfiguration to 500', () => {
    expect(
      map(new AuthenticationMisconfiguredException('profile is inactive'))?.getStatus(),
    ).toBe(HttpStatus.INTERNAL_SERVER_ERROR);
  });
});
