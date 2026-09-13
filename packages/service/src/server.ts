import { createServer, type Server, type IncomingMessage, type ServerResponse } from "node:http";
import { jstr } from "@latticeag/weather-core";
import { Fleet } from "./fleet.js";
import { Rpc } from "./rpc.js";

/**
 * Local reference transport (§6.1): POST /v1/rpc, GET /healthz, GET /readyz;
 * every other path is a bare 404. Loopback only — TLS termination is a
 * deployment concern.
 */
export function serve(opts: {
  fleet: Fleet;
  listen: string; // host:port
}): Server {
  const rpc = new Rpc(opts.fleet);
  const [host, portS] = opts.listen.split(":");
  const port = Number(portS);
  if (host !== "127.0.0.1" && host !== "::1" && host !== "localhost") {
    throw new Error("serve: refusing non-loopback listen address without TLS termination config");
  }

  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const url = req.url ?? "/";
    if (req.method === "GET" && url === "/healthz") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(jstr({ ok: true, protocol: "weather/1" }));
      return;
    }
    if (req.method === "GET" && url === "/readyz") {
      const ready = opts.fleet.phase !== "LOCKED";
      res.writeHead(ready ? 200 : 503, { "content-type": "application/json" });
      res.end(jstr({ ready }));
      return;
    }
    if (req.method !== "POST" || url !== "/v1/rpc") {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(jstr({ error: { code: "NOT_FOUND" } }));
      return;
    }
    const chunks: Buffer[] = [];
    let total = 0;
    req.on("data", (c: Buffer) => {
      total += c.length;
      if (total > 1048576 + 1) { req.destroy(); return; }
      chunks.push(c);
    });
    req.on("end", () => {
      try {
        const out = rpc.handle(Buffer.concat(chunks), BigInt(Date.now()));
        res.writeHead(out.status, { "content-type": "application/json" });
        res.end(jstr(out.body));
      } catch {
        res.writeHead(400, { "content-type": "application/json" });
        res.end(jstr({ error: { code: "INVALID_INPUT" } }));
      }
    });
    req.on("error", () => { try { res.destroy(); } catch { /* ignore */ } });
  });
  server.listen(port, host);
  return server;
}
