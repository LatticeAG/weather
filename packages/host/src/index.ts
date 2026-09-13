import { parseText, isId } from "@latticeag/weather-core";

/**
 * Hosted Weather surface (Workers ingress, per-fleet Durable Object,
 * Access-gated fleet view, primary-URL paging transport) is outside the OSS
 * core. These are honest stubs: they fail closed and never pretend to serve.
 *
 * The only locally implementable pieces are the pure validators for the
 * deployment bindings — the hosted mapping schema and the primary notification
 * URL policy — which are exported so deployments and tests can check their
 * configuration without standing up hosted infrastructure.
 */

export interface HostedMappingBinding {
  subject: string;
  fleet: string;
  principal: string;
  role: "reader" | "operator";
}

export interface HostedMapping {
  v: 1;
  issuer: string;
  audience: string;
  bindings: HostedMappingBinding[];
}

function ni(what: string): never {
  const e = new Error(
    `${what} is not part of the OSS core build. See README.md for the ` +
    "open-source boundary and https://devin.ai/support for the hosted offering.");
  e.name = "NotImplemented";
  throw e;
}

/** Cloudflare Workers fetch entry — hosted ingress only. */
export function workerFetch(): never {
  return ni("Hosted Weather ingress (Cloudflare Worker + FleetDO bindings)");
}

/** Hosted fleet view (Access-gated reader/operator UI). */
export function hostedView(): never {
  return ni("Hosted fleet view (Cloudflare Access + per-fleet DO reads)");
}

/** Primary notification transport (HTTPS:443 public-IP enforced paging). */
export function deliverPage(): never {
  return ni("Hosted paging transport (HTTPS:443 public egress)");
}

/**
 * Validate the hosted identity mapping document
 * `{v:1,issuer,audience,bindings:[{subject,fleet,principal,role}]}`
 * (§9): bindings sort by subject/fleet and conflicting duplicates reject.
 */
export function validateHostedMapping(text: string): HostedMapping {
  const m = parseText(text) as HostedMapping;
  if (typeof m !== "object" || m === null || m.v !== 1 ||
    typeof m.issuer !== "string" || typeof m.audience !== "string" ||
    !Array.isArray(m.bindings)) {
    throw new Error("hosted mapping: invalid shape");
  }
  let prev: HostedMappingBinding | null = null;
  for (const b of m.bindings) {
    if (typeof b.subject !== "string" || !isId(b.fleet, "wfl") ||
      !isId(b.principal, "wpr") || (b.role !== "reader" && b.role !== "operator")) {
      throw new Error("hosted mapping: invalid binding");
    }
    if (prev && (b.subject < prev.subject ||
      (b.subject === prev.subject && b.fleet <= prev.fleet))) {
      if (b.subject === prev.subject && b.fleet === prev.fleet) {
        throw new Error("hosted mapping: conflicting duplicate binding");
      }
      throw new Error("hosted mapping: bindings not sorted by subject/fleet");
    }
    prev = b;
  }
  return m;
}

/**
 * Validate a primary notification URL: HTTPS on port 443, fixed path, no
 * query/fragment/credentials. Redirects are not followed by contract.
 */
export function validatePrimaryUrl(url: string | null): string | null {
  if (url === null) return null;
  const u = new URL(url);
  if (u.protocol !== "https:" || u.port !== "" && u.port !== "443" ||
    u.username !== "" || u.password !== "" || u.search !== "" || u.hash !== "" ||
    u.pathname === "" || u.pathname === "/") {
    throw new Error("primary_url: must be https:443 with a fixed path and no query/fragment/credentials");
  }
  return url;
}
