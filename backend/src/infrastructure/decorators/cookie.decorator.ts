import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import type { Request } from 'express';

export const Cookie = createParamDecorator(
  (data: string, ctx: ExecutionContext): string | undefined => {
    const request = ctx.switchToHttp().getRequest<Request>();

    return data ? (request.cookies?.[data] as string) : undefined;
  },
);
