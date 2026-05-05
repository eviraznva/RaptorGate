import { createServer as createHttpsServer } from "node:https";
import type { ServerOptions as HttpsServerOptions } from "node:https";
import type { Server as HttpServer } from "node:http";
import type { Server as HttpsServer } from "node:https";
import { Logger } from "@nestjs/common";
import { IoAdapter } from "@nestjs/platform-socket.io";
import { Server as SocketIoServer } from "socket.io";
import type { ServerOptions } from "socket.io";

type GatewayOptions = Partial<ServerOptions> & { namespace?: string };

export class MultiPortSocketIoAdapter extends IoAdapter {
  private readonly logger = new Logger(MultiPortSocketIoAdapter.name);
  private readonly servers = new Map<number, HttpServer | HttpsServer>();
  private readonly ioInstances = new Map<number, SocketIoServer>();

  constructor(
    app: any,
    private readonly httpsOptions?: HttpsServerOptions,
  ) {
    super(app);
  }

  override createIOServer(port: number, options?: GatewayOptions): any {
    const namespace = options?.namespace;
    const serverOptions = { ...options };
    delete serverOptions.namespace;

    const io = this.getOrCreateServer(port, serverOptions);
    return namespace ? io.of(namespace) : io;
  }

  override async close(server: SocketIoServer): Promise<void> {
    for (const [port, srv] of this.servers) {
      await new Promise<void>((resolve, reject) => {
        srv.close((err) => {
          if (err) {
            this.logger.error(`Error closing WS server on port ${port}: ${err.message}`);
            reject(err);
          } else {
            this.logger.log(`WebSocket server on port ${port} closed`);
            resolve();
          }
        });
      });
    }
    this.servers.clear();
    this.ioInstances.clear();
    await super.close(server);
  }

  private getOrCreateServer(
    port: number,
    options?: Partial<ServerOptions>,
  ): SocketIoServer {
    const existing = this.ioInstances.get(port);
    if (existing) return existing;

    const httpServer: HttpServer = this.httpsOptions
      ? createHttpsServer(this.httpsOptions)
      : createHttpsServer();

    const io = new SocketIoServer(httpServer as any, {
      ...options,
      cors: { origin: true, credentials: true },
    });

    httpServer.listen(port, () => {
      this.logger.log(`WebSocket server listening on port ${port}`);
    });

    this.servers.set(port, httpServer);
    this.ioInstances.set(port, io);

    return io;
  }
}
