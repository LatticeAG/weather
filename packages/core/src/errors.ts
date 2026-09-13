/** Protocol error codes, §6.1. */
export type Code =
  | "INVALID_INPUT" | "UNSUPPORTED_VERSION" | "UNAUTHORIZED" | "FORBIDDEN"
  | "NOT_FOUND" | "HASH_MISMATCH" | "SIGNATURE_INVALID" | "KEY_REVOKED"
  | "FUTURE_TIMESTAMP" | "STALE_REQUEST" | "IDEMPOTENCY_CONFLICT"
  | "REPLAY_EXPIRED" | "REVISION_CONFLICT" | "STATE_CONFLICT" | "CHAIN_INVALID"
  | "SOURCE_FORKED" | "SOURCE_TERMINAL" | "GAP_LIMIT" | "USAGE_CONFLICT"
  | "RESULT_MISMATCH" | "VOTE_EXPIRED" | "CURSOR_INVALID" | "PACK_UNAVAILABLE"
  | "CAPACITY" | "BUSY" | "AUDIT_UNAVAILABLE";

export class WError extends Error {
  constructor(
    readonly code: Code,
    message?: string,
    readonly retryable = false,
  ) {
    super(message ?? code);
    this.name = "WError";
  }
}

export const err = (code: Code, message?: string, retryable = false): never => {
  throw new WError(code, message, retryable);
};

/** Total HTTP mapping over Code, §6.1. */
export const HTTP_STATUS: Record<Code, number> = {
  INVALID_INPUT: 400,
  UNSUPPORTED_VERSION: 400,
  UNAUTHORIZED: 401,
  STALE_REQUEST: 401,
  FORBIDDEN: 403,
  KEY_REVOKED: 403,
  NOT_FOUND: 404,
  HASH_MISMATCH: 422,
  SIGNATURE_INVALID: 422,
  IDEMPOTENCY_CONFLICT: 409,
  REPLAY_EXPIRED: 409,
  REVISION_CONFLICT: 409,
  STATE_CONFLICT: 409,
  CHAIN_INVALID: 409,
  SOURCE_FORKED: 409,
  SOURCE_TERMINAL: 409,
  GAP_LIMIT: 409,
  USAGE_CONFLICT: 409,
  RESULT_MISMATCH: 409,
  VOTE_EXPIRED: 409,
  CURSOR_INVALID: 409,
  FUTURE_TIMESTAMP: 409,
  CAPACITY: 429,
  BUSY: 503,
  PACK_UNAVAILABLE: 503,
  AUDIT_UNAVAILABLE: 503,
};

/** CLI exit-code mapping, §7.1. */
export function exitCodeFor(code: Code): number {
  switch (code) {
    case "INVALID_INPUT":
    case "UNSUPPORTED_VERSION":
      return 2;
    case "UNAUTHORIZED":
    case "FORBIDDEN":
    case "SIGNATURE_INVALID":
    case "KEY_REVOKED":
    case "STALE_REQUEST":
      return 3;
    case "REVISION_CONFLICT":
    case "STATE_CONFLICT":
    case "IDEMPOTENCY_CONFLICT":
    case "REPLAY_EXPIRED":
    case "CHAIN_INVALID":
    case "SOURCE_FORKED":
    case "SOURCE_TERMINAL":
    case "GAP_LIMIT":
    case "USAGE_CONFLICT":
    case "RESULT_MISMATCH":
    case "VOTE_EXPIRED":
    case "CURSOR_INVALID":
    case "HASH_MISMATCH":
    case "NOT_FOUND":
      return 4;
    case "CAPACITY":
    case "BUSY":
    case "PACK_UNAVAILABLE":
    case "AUDIT_UNAVAILABLE":
      return 7;
    case "FUTURE_TIMESTAMP":
      return 4;
  }
}
