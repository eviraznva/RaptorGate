import {
  CallHandler,
  ExecutionContext,
  Injectable,
  Logger,
  NestInterceptor,
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import type { Request, Response } from "express";
import { map } from "rxjs/operators";
import { RESPONSE_MESSAGE_KEY } from "../decorators/response-message.decorator.js";

@Injectable()
export class SuccessEnvelopeInterceptor implements NestInterceptor {
  private readonly logger = new Logger(SuccessEnvelopeInterceptor.name);

  constructor(private readonly reflector: Reflector) {}

  intercept(context: ExecutionContext, next: CallHandler) {
    if (context.getType() !== "http") return next.handle();

    const http = context.switchToHttp();
    const req = http.getRequest<Request>();
    const res = http.getResponse<Response>();
    const startedAt = Date.now();

    const customMessage = this.reflector.getAllAndOverride<string>(
      RESPONSE_MESSAGE_KEY,
      [context.getHandler(), context.getClass()],
    );

    return next.handle().pipe(
      map((data: unknown) => {
        const message =
          customMessage ?? this.defaultMessage(req.method, res.statusCode);

        this.logger.log({
          event: "http.request.completed",
          message,
          method: req.method,
          path: req.originalUrl ?? req.url,
          statusCode: res.statusCode,
          durationMs: Date.now() - startedAt,
          userId: getRequestUserId(req),
        });

        return {
          statusCode: res.statusCode,
          message,
          data: data ?? null,
        };
      }),
    );
  }

  private defaultMessage(method: string, status: number): string {
    if (method === "POST" && status === 201) return "Resource created";
    if (method === "DELETE") return "Resource deleted";
    if (method === "PUT" || method === "PATCH") return "Resource updated";
    return "Success";
  }
}

function getRequestUserId(req: Request): string | undefined {
  const user = (req as Request & { user?: { id?: unknown; sub?: unknown } }).user;
  if (typeof user?.id === "string") return user.id;
  if (typeof user?.sub === "string") return user.sub;
  return undefined;
}
