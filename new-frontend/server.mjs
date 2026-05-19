import app from "./dist/server/server.js";

const port = Number(process.env.PORT ?? 3100);
const hostname = process.env.HOST ?? "127.0.0.1";

Bun.serve({
	hostname,
	port,
	fetch: (request) => app.fetch(request),
});

console.log(`RaptorGate new frontend listening on http://${hostname}:${port}`);
