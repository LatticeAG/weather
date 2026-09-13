import {
  D, jstr, parseBytes, newId, signDetached, b64uEncode, exitCodeFor,
} from "@latticeag/weather-core";
import type { ClientConfig, PrivateKeyFile, Method, RequestEnvelope, Code } from "@latticeag/weather-core";
import { CliError } from "./files.js";

/** Signed RequestEnvelope POST /v1/rpc client (§6.1, §7.1). */
export class Client {
  constructor(
    private cfg: ClientConfig,
    private key: PrivateKeyFile,
  ) {}

  /**
   * One logical call. On an ambiguous transport outcome (timeout / connection
   * failure / 5xx without a protocol body) the *original complete signed body*
   * is retried once — the request ID is never silently regenerated.
   */
  async call<M extends Method>(method: M, params: Record<string, unknown>): Promise<unknown> {
    const body = {
      v: 1 as const, fleet: this.cfg.fleet, id: newId("wrq"),
      key_id: this.key.key_id, sent_ms: Date.now().toString(),
      method, params,
    } as RequestEnvelope["body"];
    const hash = D("WEATHER-REQUEST/1", body);
    const env: RequestEnvelope = {
      body, hash,
      sig: b64uEncode(signDetached(Buffer.from(this.key.seed, "base64url"), "WEATHER-REQUEST-SIGN/1", hash)),
    };
    const payload = jstr(env);
    let lastErr: CliError | null = null;
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        return await this.post(payload);
      } catch (e) {
        if (e instanceof CliError && e.code === 7) { lastErr = e; continue; } // ambiguous: retry same bytes
        throw e;
      }
    }
    throw lastErr ?? new CliError(7, "request failed");
  }

  private async post(payload: string): Promise<unknown> {
    const url = `${this.cfg.endpoint}/v1/rpc`;
    let res: Response;
    try {
      res = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: payload,
        signal: AbortSignal.timeout(this.cfg.timeout_ms),
      });
    } catch (e) {
      throw new CliError(7, `connection failed: ${(e as Error).message}`);
    }
    const raw = Buffer.from(await res.arrayBuffer());
    let parsed: unknown;
    try { parsed = parseBytes(raw); }
    catch { throw new CliError(7, `unparseable response (HTTP ${res.status})`); }
    const r = parsed as { ok?: boolean; result?: unknown; error?: { code?: Code; retryable?: boolean } };
    if (r && typeof r === "object" && "ok" in r) {
      if (r.ok === true) return r.result;
      const code = r.error?.code ?? "INVALID_INPUT";
      throw new CliError(exitCodeFor(code), `RPC ${code}`);
    }
    const bare = (r as { error?: { code?: Code } })?.error?.code;
    if (bare) throw new CliError(exitCodeFor(bare), `RPC ${bare}`);
    throw new CliError(7, `malformed response (HTTP ${res.status})`);
  }
}
