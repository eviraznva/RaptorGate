import { Inject, Logger, OnModuleDestroy } from "@nestjs/common";
import {
  OnGatewayConnection,
  OnGatewayDisconnect,
  OnGatewayInit,
  WebSocketGateway,
  WebSocketServer,
} from "@nestjs/websockets";
import { Subscription } from "rxjs";
import { Server, Socket } from "socket.io";
import type { ITokenService } from "../../application/ports/token-service.interface.js";
import { TOKEN_SERVICE_TOKEN } from "../../application/ports/token-service.interface.js";
import { Permission } from "../../domain/enums/permissions.enum.js";
import { Role as RoleName } from "../../domain/enums/role.enum.js";
import type { IRoleRepository } from "../../domain/repositories/role.repository.js";
import { ROLE_REPOSITORY_TOKEN } from "../../domain/repositories/role.repository.js";
import { GetTcpSessionsResponseDto } from "../../presentation/dtos/get-tcp-sessions-response.dto.js";
import { TcpTrackedSessionResponseMapper } from "../../presentation/mappers/tcp-tracked-session-response.mapper.js";
import { GrpcFirewallConntrackMetricsStreamService } from "./grpc-firewall-conntrack-metrics-stream.service.js";
import { GrpcFirewallTcpSessionsQueryService } from "./grpc-firewall-tcp-sessions-query.service.js";
import { TcpSessionsConntrackMapper } from "./tcp-sessions-conntrack.mapper.js";

@WebSocketGateway(2000, {
  namespace: "/sessions",
  cors: {
    origin: true,
    credentials: true,
  },
})
export class SessionsGateway
  implements OnGatewayInit, OnGatewayConnection, OnGatewayDisconnect, OnModuleDestroy
{
  @WebSocketServer()
  server!: Server;

  private readonly logger = new Logger(SessionsGateway.name);
  private readonly subscriptions = new Subscription();

  constructor(
    private readonly conntrackMetricsStream: GrpcFirewallConntrackMetricsStreamService,
    private readonly tcpSessionsQuery: GrpcFirewallTcpSessionsQueryService,
    @Inject(TOKEN_SERVICE_TOKEN)
    private readonly tokenService: ITokenService,
    @Inject(ROLE_REPOSITORY_TOKEN)
    private readonly roleRepository: IRoleRepository,
  ) {}

  afterInit(server: Server) {
    server.use((client, next) => {
      void this.authorizeClient(client)
        .then(() => next())
        .catch((error: unknown) => {
          const message = error instanceof Error ? error.message : "Unauthorized";
          next(new Error(message));
        });
    });

    this.subscriptions.add(
      this.conntrackMetricsStream.conntrackMetrics$.subscribe((update) => {
        this.server.emit(
          "tcpSessions",
          this.toResponse(TcpSessionsConntrackMapper.toTcpTrackedSessions(update)),
        );
      }),
    );
  }

  async handleConnection(client: Socket) {
    this.logger.log(`Sessions client connected: ${client.id}`);

    const tcpSessions = await this.tcpSessionsQuery.getTcpSessions();
    client.emit("tcpSessions", this.toResponse(tcpSessions));
  }

  handleDisconnect(client: Socket) {
    this.logger.log(`Sessions client disconnected: ${client.id}`);
  }

  onModuleDestroy() {
    this.subscriptions.unsubscribe();
  }

  private async authorizeClient(client: Socket): Promise<void> {
    const token = this.extractToken(client);
    if (!token) throw new Error("Missing or invalid token");

    const payload = await this.tokenService.verifyAccessToken(token);
    if (!payload) throw new Error("Invalid or expired token");

    const roles = await this.roleRepository.findByUserId(payload.sub);
    const hasViewerRole = roles.some((role) => role.getName() === RoleName.Viewer);
    const hasFirewallStatus = roles.some((role) =>
      role.hasPermission(Permission.FIREWALL_STATUS),
    );

    if (!hasViewerRole || !hasFirewallStatus) {
      throw new Error("Forbidden: insufficient permissions");
    }
  }

  private extractToken(client: Socket): string | undefined {
    const authToken = client.handshake.auth?.token;
    if (typeof authToken === "string" && authToken.length > 0) return authToken;

    const authorization = client.handshake.headers.authorization;
    const header = Array.isArray(authorization) ? authorization[0] : authorization;
    const [type, token] = header?.split(" ") ?? [];

    return type === "Bearer" ? token : undefined;
  }

  private toResponse(
    tcpSessions: Parameters<typeof TcpTrackedSessionResponseMapper.toDto>[0][],
  ): GetTcpSessionsResponseDto {
    return {
      tcpSessions: tcpSessions.map((tcpSession) =>
        TcpTrackedSessionResponseMapper.toDto(tcpSession),
      ),
    };
  }
}
