// Canonical error envelope (architecture spec §2.8):
//   { "error": { "code": "snake_case", "message": "human", "retry_after": 0 } }

export type ErrorCode =
  | "unauthenticated"
  | "forbidden"
  | "not_found"
  | "conflict"
  | "gone"
  | "rate_limited"
  | "payload_too_large"
  | "malformed"
  | "rollback_detected"
  | "internal"
  | "network"
  | "unknown";

export interface ErrorEnvelope {
  error: { code: string; message: string; retry_after?: number };
}

export class ApiError extends Error {
  readonly code: ErrorCode;
  readonly status: number;
  readonly retryAfter: number;

  constructor(code: ErrorCode, message: string, status: number, retryAfter = 0) {
    super(message);
    this.name = "ApiError";
    this.code = code;
    this.status = status;
    this.retryAfter = retryAfter;
  }

  /** A 401/403 demands re-authenticating with the keyset. */
  get needsAuth(): boolean {
    return this.code === "unauthenticated" || this.code === "forbidden";
  }
  get isTransient(): boolean {
    return this.code === "rate_limited" || this.status >= 500;
  }
}

const KNOWN: ReadonlySet<string> = new Set([
  "unauthenticated",
  "forbidden",
  "not_found",
  "conflict",
  "gone",
  "rate_limited",
  "payload_too_large",
  "malformed",
  "rollback_detected",
  "internal",
]);

export async function errorFromResponse(res: Response): Promise<ApiError> {
  let code: ErrorCode = "unknown";
  let message = `HTTP ${res.status}`;
  let retryAfter = Number(res.headers.get("retry-after") ?? 0) || 0;
  try {
    const body = (await res.json()) as Partial<ErrorEnvelope>;
    if (body?.error) {
      if (KNOWN.has(body.error.code)) code = body.error.code as ErrorCode;
      // The message comes from the (untrusted) server and is rendered in the admin chrome.
      // React escapes the text (no XSS), but we cap the length so the server can't
      // shove a huge/abusive string into the UI.
      if (body.error.message) message = String(body.error.message).slice(0, 300);
      if (typeof body.error.retry_after === "number" && body.error.retry_after > 0) {
        retryAfter = body.error.retry_after;
      }
    }
  } catch {
    // non-JSON body → keep defaults
  }
  if (code === "unknown") {
    if (res.status === 401) code = "unauthenticated";
    else if (res.status === 403) code = "forbidden";
    else if (res.status === 404) code = "not_found";
    else if (res.status === 409) code = "conflict";
    else if (res.status === 429) code = "rate_limited";
    else if (res.status >= 500) code = "internal";
  }
  return new ApiError(code, message, res.status, retryAfter);
}
