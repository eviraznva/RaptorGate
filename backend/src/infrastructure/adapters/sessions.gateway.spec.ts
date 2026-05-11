import { beforeEach, describe, expect, it, jest } from "@jest/globals";
import { Subject } from "rxjs";
import type { Server, Socket } from "socket.io";
import type {
  ConntrackFlowDto,
  ConntrackMetricsUpdateDto,
} from "../../application/dtos/conntrack-metrics.dto.js";
import { Permission as PermissionEntity } from "../../domain/entities/permission.entity.js";
import { Role as RoleEntity } from "../../domain/entities/role.entity.js";
import { Permission } from "../../domain/enums/permissions.enum.js";
import { Role } from "../../domain/enums/role.enum.js";
import {
  TcpSessionEndpoint,
  TcpTrackedSession,
  type TcpTrackedSessionDetails,
} from "../../domain/entities/tcp-tracked-session.entity.js";
import { IpAddress } from "../../domain/value-objects/ip-address.vo.js";
import { Port } from "../../domain/value-objects/port.vo.js";
import type { GrpcFirewallConntrackMetricsStreamService } from "./grpc-firewall-conntrack-metrics-stream.service.js";
import type { GrpcFirewallTcpSessionsQueryService } from "./grpc-firewall-tcp-sessions-query.service.js";
import { SessionsGateway } from "./sessions.gateway.js";

type Middleware = (client: Socket, next: (err?: Error) => void) => void;

const flushPromises = () => new Promise<void>((resolve) => setImmediate(resolve));

const details: TcpTrackedSessionDetails = {
  id: "1",
  lifecycle: "active",
  lastDirection: "original",
  interfaces: {
    originalIngress: "wan0",
    originalEgress: "lan0",
    replyIngress: "lan0",
    replyEgress: "wan0",
  },
  mark: 0,
  statusBits: 0,
  bytesOriginal: 100,
  bytesReply: 200,
  packetsOriginal: 1,
  packetsReply: 2,
  createdAt: "2026-05-09T10:00:00.000Z",
  lastSeenAt: "2026-05-09T10:00:05.000Z",
  expiresAt: "2026-05-09T10:01:00.000Z",
  destroyReason: "unspecified",
};

const makeFlow = (overrides: Partial<ConntrackFlowDto> = {}): ConntrackFlowDto => ({
  id: "1",
  lifecycle: "active",
  state: "established",
  lastDirection: "original",
  original: {
    srcIp: "192.168.1.10",
    srcPort: 52341,
    dstIp: "10.0.0.20",
    dstPort: 443,
    protocol: "tcp",
  },
  reply: {
    srcIp: "10.0.0.20",
    srcPort: 443,
    dstIp: "192.168.1.10",
    dstPort: 52341,
    protocol: "tcp",
  },
  interfaces: details.interfaces,
  mark: 0,
  statusBits: 0,
  bytesOriginal: 100,
  bytesReply: 200,
  packetsOriginal: 1,
  packetsReply: 2,
  createdAt: details.createdAt,
  lastSeenAt: details.lastSeenAt,
  expiresAt: details.expiresAt,
  destroyReason: "unspecified",
  ...overrides,
});

const update = (flows: ConntrackFlowDto[]): ConntrackMetricsUpdateDto => ({
  timestamp: "2026-05-09T10:00:05.000Z",
  flows,
});

const makeSession = () =>
  TcpTrackedSession.create(
    TcpSessionEndpoint.create(IpAddress.create("192.168.1.10"), Port.create(52341)),
    TcpSessionEndpoint.create(IpAddress.create("10.0.0.20"), Port.create(443)),
    "established",
    details,
  );

const makeViewerRole = () =>
  RoleEntity.create("viewer", Role.Viewer, null, [
    PermissionEntity.create("firewall-status", Permission.FIREWALL_STATUS),
  ]);

const makeSocket = (token?: string): Socket =>
  ({
    id: "socket-1",
    emit: jest.fn(),
    handshake: {
      auth: token ? { token } : {},
      headers: {},
    },
  }) as unknown as Socket;

const createGateway = () => {
  const conntrackMetrics = new Subject<ConntrackMetricsUpdateDto>();
  const conntrackMetricsStream = {
    conntrackMetrics$: conntrackMetrics.asObservable(),
  } as unknown as GrpcFirewallConntrackMetricsStreamService;
  const tcpSessionsQuery = {
    getTcpSessions: jest.fn<() => Promise<TcpTrackedSession[]>>(),
  } as unknown as GrpcFirewallTcpSessionsQueryService;
  const tokenService = {
    verifyAccessToken: jest.fn<() => Promise<{ sub: string; username: string } | null>>(),
  };
  const roleRepository = {
    findByUserId: jest.fn<() => Promise<RoleEntity[]>>(),
  };
  let middleware: Middleware | undefined;
  const server = {
    use: jest.fn((handler: Middleware) => {
      middleware = handler;
      return server;
    }),
    emit: jest.fn(),
  };

  const gateway = new SessionsGateway(
    conntrackMetricsStream,
    tcpSessionsQuery,
    tokenService,
    roleRepository,
  );
  gateway.server = server as unknown as Server;

  return {
    gateway,
    conntrackMetrics,
    tcpSessionsQuery,
    tokenService,
    roleRepository,
    server,
    getMiddleware: () => middleware,
  };
};

describe("SessionsGateway", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("emits TCP sessions from conntrack stream", () => {
    const { gateway, conntrackMetrics, server } = createGateway();
    gateway.afterInit(server as unknown as Server);

    conntrackMetrics.next(update([makeFlow()]));

    expect(server.emit).toHaveBeenCalledWith("tcpSessions", {
      tcpSessions: [
        {
          endpointA: { ip: "192.168.1.10", port: 52341 },
          endpointB: { ip: "10.0.0.20", port: 443 },
          state: "established",
          ...details,
        },
      ],
    });
  });

  it("filters non-TCP and destroyed flows", () => {
    const { gateway, conntrackMetrics, server } = createGateway();
    gateway.afterInit(server as unknown as Server);

    conntrackMetrics.next(
      update([
        makeFlow({ original: { ...makeFlow().original, protocol: "udp" } }),
        makeFlow({ lifecycle: "destroyed", destroyReason: "timeout" }),
      ]),
    );

    expect(server.emit).toHaveBeenCalledWith("tcpSessions", { tcpSessions: [] });
  });

  it("emits snapshot on connection", async () => {
    const { gateway, tcpSessionsQuery } = createGateway();
    const socket = makeSocket("valid-token");
    tcpSessionsQuery.getTcpSessions.mockResolvedValue([makeSession()]);

    await gateway.handleConnection(socket);

    expect(socket.emit).toHaveBeenCalledWith("tcpSessions", {
      tcpSessions: [
        {
          endpointA: { ip: "192.168.1.10", port: 52341 },
          endpointB: { ip: "10.0.0.20", port: 443 },
          state: "established",
          ...details,
        },
      ],
    });
  });

  it("rejects missing token", async () => {
    const { gateway, server, getMiddleware } = createGateway();
    gateway.afterInit(server as unknown as Server);
    const next = jest.fn();

    const middleware = getMiddleware();
    expect(middleware).toBeDefined();
    middleware?.(makeSocket(), next);
    await flushPromises();

    expect(next).toHaveBeenCalledWith(expect.objectContaining({ message: "Missing or invalid token" }));
  });

  it("rejects user without firewall status permission", async () => {
    const { gateway, server, getMiddleware, tokenService, roleRepository } = createGateway();
    gateway.afterInit(server as unknown as Server);
    tokenService.verifyAccessToken.mockResolvedValue({ sub: "user-1", username: "viewer" });
    roleRepository.findByUserId.mockResolvedValue([
      RoleEntity.create("viewer", Role.Viewer, null, []),
    ]);
    const next = jest.fn();

    const middleware = getMiddleware();
    expect(middleware).toBeDefined();
    middleware?.(makeSocket("valid-token"), next);
    await flushPromises();

    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({ message: "Forbidden: insufficient permissions" }),
    );
  });

  it("allows viewer with firewall status permission", async () => {
    const { gateway, server, getMiddleware, tokenService, roleRepository } = createGateway();
    gateway.afterInit(server as unknown as Server);
    tokenService.verifyAccessToken.mockResolvedValue({ sub: "user-1", username: "viewer" });
    roleRepository.findByUserId.mockResolvedValue([makeViewerRole()]);
    const next = jest.fn();

    const middleware = getMiddleware();
    expect(middleware).toBeDefined();
    middleware?.(makeSocket("valid-token"), next);
    await flushPromises();

    expect(next).toHaveBeenCalledWith();
  });
});
