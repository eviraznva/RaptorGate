import {
  ExecutionContext,
  NestInterceptor,
  CallHandler,
  Injectable,
} from '@nestjs/common';
import { RESPONSE_MESSAGE_KEY } from '../decorators/response-message.decorator.js';
import type { Request, Response } from 'express';
import { Reflector } from '@nestjs/core';
import { map } from 'rxjs/operators';

@Injectable()
export class SuccessEnvelopeInterceptor implements NestInterceptor {
  constructor(private readonly reflector: Reflector) {}

  intercept(context: ExecutionContext, next: CallHandler) {
    if (context.getType() !== 'http') return next.handle();

    const http = context.switchToHttp();
    const req = http.getRequest<Request>();
    const res = http.getResponse<Response>();

    const customMessage = this.reflector.getAllAndOverride<string>(
      RESPONSE_MESSAGE_KEY,
      [context.getHandler(), context.getClass()],
    );

    return next.handle().pipe(
      map((data: unknown) => ({
        statusCode: res.statusCode,
        message:
          customMessage ?? this.defaultMessage(req.method, res.statusCode),
        data: data ?? null,
      })),
    );
  }

  private defaultMessage(method: string, status: number): string {
    if (method === 'POST' && status === 201) return 'Resource created';
    if (method === 'DELETE') return 'Resource deleted';
    if (method === 'PUT' || method === 'PATCH') return 'Resource updated';
    return 'Success';
  }
}
