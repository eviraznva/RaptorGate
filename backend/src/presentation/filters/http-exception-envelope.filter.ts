import {
  ArgumentsHost,
  BadRequestException,
  Catch,
  ConflictException,
  ExceptionFilter,
  HttpException,
  HttpStatus,
  NotFoundException,
  UnauthorizedException,
} from "@nestjs/common";
import type { Response } from "express";
import { AccessTokenIsInvalidException } from "../../domain/exceptions/acces-token-is-invalid.exception.js";
import { AtLeastOneFieldRequiredException } from "../../domain/exceptions/at-least-one-field-required.exception.js";
import { ChecksumIsInvalidException } from "../../domain/exceptions/checksum-is-invalid.exception.js";
import { DomainNameIsInvalidException } from "../../domain/exceptions/domain-name-is-invalid.exception.js";
import { EmailIsInvalidException } from "../../domain/exceptions/email-is-invalid.exception.js";
import { EntityAlreadyExistsException } from "../../domain/exceptions/entity-already-exists-exception.js";
import { EntityNotFoundException } from "../../domain/exceptions/entity-not-found-exception.js";
import { InvalidCredentialsException } from "../../domain/exceptions/invalid-credentials.exception.js";
import { IpAddressIsInvalidException } from "../../domain/exceptions/ip-address-is-invalid.exception.js";
import { IpsSignatureCategoryIsInvalidException } from "../../domain/exceptions/ips-signature-category-is-invalid.exception.js";
import { MacAddressIsInvalidException } from "../../domain/exceptions/mac-address-is-invalid.exception.js";
import { NatConfigIsInvalidException } from "../../domain/exceptions/nat-config-is-invalid.exception.js";
import { NatTypeIsInvalidException } from "../../domain/exceptions/nat-type-is-invalid.exception.js";
import { PortIsInvalidException } from "../../domain/exceptions/port-is-invalid.exception.js";
import { PriorityIsInvalidException } from "../../domain/exceptions/priority-is-invalid.exception.js";
import { RaptorLangValidationException } from "../../domain/exceptions/raptor-lang-validation.exception.js";
import { RefreshTokenIsInvalidException } from "../../domain/exceptions/refresh-token-is-invalid.exception.js";
import { RegexPatternIsInvalidException } from "../../domain/exceptions/regex-pattern-is-invalid.exception.js";
import { SemanticVersionIsInvalidException } from "../../domain/exceptions/semantic-version-is-invalid.exception.js";
import { SnapshotTypeIsInvalidException } from "../../domain/exceptions/snapshot-type-is-invalid.exception.js";
import { UserAlreadyExistsException } from "../../domain/exceptions/user-already-exitst.exception.js";
import { UserNotFoundException } from "../../domain/exceptions/user-not-found.exception.js";
import { UserSourceIsInvalidException } from "../../domain/exceptions/user-source-is-invalid.exception.js";

@Catch()
export class HttpExceptionEnvelopeFilter implements ExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost) {
    const context = host.switchToHttp();
    const res = context.getResponse<Response>();

    const mapped = this.mapDomainToHttpException(exception);
    const err = mapped ?? exception;

    const status =
      err instanceof HttpException
        ? err.getStatus()
        : HttpStatus.INTERNAL_SERVER_ERROR;

    const response =
      err instanceof HttpException
        ? err.getResponse()
        : { message: "Internal server error" };

    const message = this.extractMessage(response); // normalizacja

    const error = this.extractError(response, status);

    res.status(status).json({ statusCode: status, message, error });
  }

  private mapDomainToHttpException(exception: unknown): HttpException | null {
    if (
      exception instanceof UserAlreadyExistsException ||
      exception instanceof EntityAlreadyExistsException
    ) {
      return new ConflictException(exception.message);
    }

    if (
      exception instanceof RefreshTokenIsInvalidException ||
      exception instanceof AccessTokenIsInvalidException
    ) {
      return new UnauthorizedException(exception.message);
    }

    if (
      exception instanceof UserNotFoundException ||
      exception instanceof EntityNotFoundException
    ) {
      return new NotFoundException(exception.message);
    }

    if (
      exception instanceof AtLeastOneFieldRequiredException ||
      exception instanceof InvalidCredentialsException ||
      exception instanceof NatConfigIsInvalidException ||
      exception instanceof ChecksumIsInvalidException ||
      exception instanceof EmailIsInvalidException ||
      exception instanceof IpAddressIsInvalidException ||
      exception instanceof IpsSignatureCategoryIsInvalidException ||
      exception instanceof MacAddressIsInvalidException ||
      exception instanceof NatTypeIsInvalidException ||
      exception instanceof PortIsInvalidException ||
      exception instanceof PriorityIsInvalidException ||
      exception instanceof RaptorLangValidationException ||
      exception instanceof RegexPatternIsInvalidException ||
      exception instanceof SemanticVersionIsInvalidException ||
      exception instanceof SnapshotTypeIsInvalidException ||
      exception instanceof UserSourceIsInvalidException ||
      exception instanceof DomainNameIsInvalidException
    ) {
      return new BadRequestException(exception.message);
    }

    return null;
  }

  private extractMessage(raw: unknown): string {
    if (typeof raw === "string") return raw;

    if (raw && typeof raw === "object") {
      const msg = (raw as { message?: unknown }).message;
      if (Array.isArray(msg)) return String(msg[0] ?? "Bad Request");

      if (typeof msg === "string") return msg;
    }

    return "Internal server error";
  }

  private extractError(raw: unknown, status: number): string {
    if (raw && typeof raw === "object") {
      const err = (raw as { error?: unknown }).error;

      if (typeof err === "string") return err;
    }
    return HttpStatus[status] ?? "Error";
  }
}
