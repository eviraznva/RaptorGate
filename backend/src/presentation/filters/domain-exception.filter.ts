import {
  BadRequestException,
  Catch,
  ConflictException,
  ExceptionFilter,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { IpsSignatureCategoryIsInvalidException } from 'src/domain/exceptions/ips-signature-category-is-invalid.exception';
import { SemanticVersionIsInvalidException } from 'src/domain/exceptions/semantic-version-is-invalid.exception';
import { AtLeastOneFieldRequiredException } from 'src/domain/exceptions/at-least-one-field-required.exception';
import { RefreshTokenIsInvalidException } from 'src/domain/exceptions/refresh-token-is-invalid.exception';
import { RegexPatternIsInvalidException } from 'src/domain/exceptions/regex-pattern-is-invalid.exception';
import { SnapshotTypeIsInvalidException } from 'src/domain/exceptions/snapshot-type-is-invalid.exception';
import { AccessTokenIsInvalidException } from 'src/domain/exceptions/acces-token-is-invalid.exception';
import { UserSourceIsInvalidException } from 'src/domain/exceptions/user-source-is-invalid.exception';
import { MacAddressIsInvalidException } from 'src/domain/exceptions/mac-address-is-invalid.exception';
import { EntityAlreadyExistsException } from 'src/domain/exceptions/entity-already-exists-exception';
import { IpAddressIsInvalidException } from 'src/domain/exceptions/ip-address-is-invalid.exception';
import { NatConfigIsInvalidException } from 'src/domain/exceptions/nat-config-is-invalid.exception';
import { InvalidCredentialsException } from 'src/domain/exceptions/invalid-credentials.exception';
import { PriorityIsInvalidException } from 'src/domain/exceptions/priority-is-invalid.exception';
import { ChecksumIsInvalidException } from 'src/domain/exceptions/checksum-is-invalid.exception';
import { UserAlreadyExistsException } from 'src/domain/exceptions/user-already-exitst.exception';
import { NatTypeIsInvalidException } from 'src/domain/exceptions/nat-type-is-invalid.exception';
import { EmailIsInvalidException } from 'src/domain/exceptions/email-is-invalid.exception';
import { EntityNotFoundException } from 'src/domain/exceptions/entity-not-found-exception';
import { PortIsInvalidException } from 'src/domain/exceptions/port-is-invalid.exception';
import { UserNotFoundException } from 'src/domain/exceptions/user-not-found.exception';

@Catch(
  IpsSignatureCategoryIsInvalidException,
  SemanticVersionIsInvalidException,
  AtLeastOneFieldRequiredException,
  RegexPatternIsInvalidException,
  RefreshTokenIsInvalidException,
  SnapshotTypeIsInvalidException,
  AccessTokenIsInvalidException,
  MacAddressIsInvalidException,
  EntityAlreadyExistsException,
  UserSourceIsInvalidException,
  InvalidCredentialsException,
  IpAddressIsInvalidException,
  NatConfigIsInvalidException,
  PriorityIsInvalidException,
  UserAlreadyExistsException,
  ChecksumIsInvalidException,
  NatTypeIsInvalidException,
  EntityNotFoundException,
  EmailIsInvalidException,
  PortIsInvalidException,
  UserNotFoundException,
)
export class DomainExceptionFilter implements ExceptionFilter {
  catch(exception: Error) {
    if (
      exception instanceof UserAlreadyExistsException ||
      exception instanceof EntityAlreadyExistsException
    ) {
      throw new ConflictException(exception.message);
    }

    if (
      exception instanceof InvalidCredentialsException ||
      exception instanceof RefreshTokenIsInvalidException ||
      exception instanceof AccessTokenIsInvalidException
    ) {
      throw new UnauthorizedException(exception.message);
    }

    if (
      exception instanceof UserNotFoundException ||
      exception instanceof EntityNotFoundException
    ) {
      throw new NotFoundException(exception.message);
    }

    if (
      exception instanceof AtLeastOneFieldRequiredException ||
      exception instanceof NatConfigIsInvalidException ||
      exception instanceof ChecksumIsInvalidException ||
      exception instanceof EmailIsInvalidException ||
      exception instanceof IpAddressIsInvalidException ||
      exception instanceof IpsSignatureCategoryIsInvalidException ||
      exception instanceof MacAddressIsInvalidException ||
      exception instanceof NatTypeIsInvalidException ||
      exception instanceof PortIsInvalidException ||
      exception instanceof PriorityIsInvalidException ||
      exception instanceof RegexPatternIsInvalidException ||
      exception instanceof SemanticVersionIsInvalidException ||
      exception instanceof SnapshotTypeIsInvalidException ||
      exception instanceof UserSourceIsInvalidException
    ) {
      throw new BadRequestException(exception.message);
    }

    throw exception;
  }
}
