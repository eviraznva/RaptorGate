import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { REQUIRE_PERMISSIONS_KEY } from '../../presentation/decorators/auth/require-permissions.decorator.js';
import { TOKEN_SERVICE_TOKEN } from '../../application/ports/token-service.interface.js';
import type { ITokenService } from '../../application/ports/token-service.interface.js';
import { ROLE_REPOSITORY_TOKEN } from '../../domain/repositories/role.repository.js';
import type { IRoleRepository } from '../../domain/repositories/role.repository.js';
import { ROLES_KEY } from '../../presentation/decorators/auth/roles.decorator.js';
import { Permission } from '../../domain/enums/permissions.enum.js';
import { Role } from '../../domain/enums/role.enum.js';
import { Reflector } from '@nestjs/core';
import { Request } from 'express';

@Injectable()
export class RolesPermissionsGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    @Inject(TOKEN_SERVICE_TOKEN) private readonly tokenService: ITokenService,
    @Inject(ROLE_REPOSITORY_TOKEN)
    private readonly roleRepository: IRoleRepository,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const requiredRoles = this.reflector.getAllAndOverride<Role[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    const requiredPermissions = this.reflector.getAllAndOverride<Permission[]>(
      REQUIRE_PERMISSIONS_KEY,
      [context.getHandler(), context.getClass()],
    );

    // Brak adnotacji @Roles i @RequirePermissions — przepuszczamy
    if (!requiredRoles && !requiredPermissions) {
      return true;
    }

    const request: Request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);

    if (!token) throw new UnauthorizedException('Missing or invalid token');
    const payload = await this.tokenService.verifyAccessToken(token);

    if (!payload) throw new UnauthorizedException('Invalid or expired token');
    const userRoles = await this.roleRepository.findByUserId(payload.sub);

    // Sprawdzenie roli
    if (requiredRoles && requiredRoles.length > 0) {
      const userRoleNames = userRoles.map((r) => r.getName());

      const hasRole = requiredRoles.some((role) =>
        userRoleNames.includes(role),
      );

      if (!hasRole) {
        throw new ForbiddenException('Forbidden: insufficient role');
      }
    }

    if (requiredPermissions && requiredPermissions.length > 0) {
      const hasAll = requiredPermissions.every((perm) =>
        userRoles.some((role) => role.hasPermission(perm)),
      );

      if (!hasAll) {
        throw new ForbiddenException('Forbidden: insufficient permissions');
      }
    }

    return true;
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];

    return type === 'Bearer' ? token : undefined;
  }
}
