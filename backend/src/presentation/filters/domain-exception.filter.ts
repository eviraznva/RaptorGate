import {
  Catch,
  ConflictException,
  ExceptionFilter,
  UnauthorizedException,
} from '@nestjs/common';
import { InvalidCredentialsException } from 'src/domain/exceptions/invalid-credentials.exception';
import { UserAlreadyExistsException } from 'src/domain/exceptions/user-already-exitst.exception';

@Catch(UserAlreadyExistsException, InvalidCredentialsException)
export class DomainExceptionFilter implements ExceptionFilter {
  catch(exception: Error) {
    if (exception instanceof UserAlreadyExistsException) {
      throw new ConflictException(exception.message);
    }

    if (exception instanceof InvalidCredentialsException) {
      throw new UnauthorizedException(exception.message);
    }

    throw exception;
  }
}
