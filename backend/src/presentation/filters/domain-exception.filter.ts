import {
  Catch,
  ConflictException,
  ExceptionFilter,
  UnauthorizedException,
  NotFoundException,
} from '@nestjs/common';
import { RefreshTokenIsInvalidException } from 'src/domain/exceptions/refresh-token-is-invalid.exception';
import { InvalidCredentialsException } from 'src/domain/exceptions/invalid-credentials.exception';
import { UserAlreadyExistsException } from 'src/domain/exceptions/user-already-exitst.exception';
import { UserNotFoundException } from 'src/domain/exceptions/user-not-found.exception';

@Catch(
  UserAlreadyExistsException,
  InvalidCredentialsException,
  RefreshTokenIsInvalidException,
  UserNotFoundException,
)
export class DomainExceptionFilter implements ExceptionFilter {
  catch(exception: Error) {
    if (exception instanceof UserAlreadyExistsException) {
      throw new ConflictException(exception.message);
    }

    if (
      exception instanceof InvalidCredentialsException ||
      exception instanceof RefreshTokenIsInvalidException
    ) {
      throw new UnauthorizedException(exception.message);
    }

    if (exception instanceof UserNotFoundException) {
      throw new NotFoundException(exception.message);
    }

    throw exception;
  }
}
