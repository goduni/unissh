import { ApiError, errorFromResponse } from "./errors";
import type {
  AccountsResp,
  AdminOverview,
  AttestationsResp,
  AuditResp,
  AuditVerify,
  AuthChallenge,
  ClaimReq,
  ClaimResp,
  ConfigPutReq,
  ConfigPutResp,
  ConfigResp,
  CreateSpaceResp,
  DevicesResp,
  DirectoryResp,
  EscrowFetchResp,
  EscrowParams,
  GrantsResp,
  HealthInfo,
  InstanceGeneration,
  InstanceInfo,
  InviteIssueReq,
  InviteIssueResp,
  InvitesResp,
  KeysetPutReq,
  KeysetPutResp,
  KeysetsResp,
  MetricsRaw,
  MetricsSummary,
  MigrationsResp,
  ObjectsResp,
  PendingResp,
  RelayResp,
  SeqBumpResp,
  SessionsResp,
  SpacesResp,
  VaultRow,
  VaultsResp,
  VerifyResp,
  VersionInfo,
} from "./types";

/** Auth/context resolved per-request from the stores (non-reactive read). */
export interface AuthContext {
  instanceUrl: string;
  /** Bearer access token (base64) from the keyset session. */
  bearer: string | null;
}

interface CallOpts {
  method?: "GET" | "POST" | "PUT";
  body?: unknown;
  /** Send Authorization: Bearer header. */
  bearer?: boolean;
  /** Attach an Idempotency-Key (mutations). */
  idem?: boolean;
  query?: Record<string, string | number | undefined | null>;
}

function uuid(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID();
  }
  return "idem-" + Math.abs(Date.now() ^ (Math.random() * 1e9)).toString(36);
}

function qs(query?: CallOpts["query"]): string {
  if (!query) return "";
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v !== undefined && v !== null && v !== "") p.set(k, String(v));
  }
  const s = p.toString();
  return s ? `?${s}` : "";
}

export function createClient(
  getAuth: () => AuthContext,
  refresh?: () => Promise<boolean>,
  /** Called when the keyset Bearer is rejected by the server and refresh couldn't
   *  rotate it. Lets the app lock instead of leaving a green badge that lies while
   *  every screen 401s. */
  onAuthLost?: (scope: "keyset") => void,
) {
  // Dedupe concurrent refreshes: when the access token lapses, many in-flight admin
  // calls 401 at the same instant. A single shared refresh avoids firing N parallel
  // /v1/session/refresh calls, which would trip the server's refresh-token REUSE
  // detection and revoke the whole session.
  let inflightRefresh: Promise<boolean> | null = null;
  function refreshOnce(): Promise<boolean> {
    if (!refresh) return Promise.resolve(false);
    if (!inflightRefresh) {
      inflightRefresh = refresh().finally(() => {
        inflightRefresh = null;
      });
    }
    return inflightRefresh;
  }

  async function call<T>(path: string, opts: CallOpts = {}, retried = false): Promise<T> {
    const auth = getAuth();
    const base = auth.instanceUrl.replace(/\/+$/, "");
    const url = base + path + qs(opts.query);
    const headers: Record<string, string> = { Accept: "application/json" };

    if (opts.bearer) {
      if (!auth.bearer) throw new ApiError("unauthenticated", "keyset locked", 401);
      headers["Authorization"] = `Bearer ${auth.bearer}`;
    }
    if (opts.idem) headers["Idempotency-Key"] = uuid();

    const init: RequestInit = { method: opts.method ?? "GET", headers };
    if (opts.body !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(opts.body);
    }

    let res: Response;
    try {
      res = await fetch(url, init);
    } catch (e) {
      throw new ApiError("network", e instanceof Error ? e.message : "network error", 0);
    }
    if (!res.ok) {
      // Access token lapsed → rotate it with the refresh token and retry once, so the
      // operator keeps working instead of being bounced to the keyset-unlock screen.
      if (res.status === 401 && opts.bearer && !retried) {
        const ok = await refreshOnce();
        if (ok) return call<T>(path, opts, true);
        // Refresh failed (session revoked, device removed): the keyset session is
        // dead. Signal it so the UI auto-locks and says so.
        onAuthLost?.("keyset");
      }
      throw await errorFromResponse(res);
    }
    if (res.status === 204) return undefined as T;
    const text = await res.text();
    if (!text) return undefined as T;
    return JSON.parse(text) as T;
  }

  return {
    call,

    // ── service (no auth) ──
    version: () => call<VersionInfo>("/v1/version"),
    readyz: async (): Promise<boolean> => {
      const auth = getAuth();
      try {
        const r = await fetch(auth.instanceUrl.replace(/\/+$/, "") + "/readyz");
        return r.ok;
      } catch {
        return false;
      }
    },

    // ── instance identity + claim (public) ──
    instance: () => call<InstanceInfo>("/v1/instance"),
    claim: (req: ClaimReq) =>
      call<ClaimResp>("/v1/claim", { method: "POST", body: req }),

    // ── escrow sign-in (public: fresh-device keyset recovery) ──
    escrowParams: (handle: string) =>
      call<EscrowParams>("/v1/escrow/params", { query: { handle } }),
    escrowFetch: (handle: string, k_auth: string) =>
      call<EscrowFetchResp>("/v1/escrow/fetch", {
        method: "POST",
        body: { handle, k_auth },
      }),

    // ── admin (Bearer + is_owner, OwnerCtx-gated) ──
    admin: {
      overview: () => call<AdminOverview>("/v1/admin/overview", { bearer: true }),
      instance: () =>
        call<InstanceGeneration>("/v1/admin/instance", { bearer: true }),
      accountStatus: (account_id: string, disabled: boolean) =>
        call<void>("/v1/admin/account/status", {
          method: "POST",
          bearer: true,
          idem: true,
          body: { account_id, disabled },
        }),
      devices: (account_id?: string) =>
        call<DevicesResp>("/v1/admin/devices", {
          bearer: true,
          query: { account_id },
        }),
      sessions: (account_id?: string) =>
        call<SessionsResp>("/v1/admin/sessions", {
          bearer: true,
          query: { account_id },
        }),
      sessionRevoke: (session_id: string) =>
        call<void>("/v1/admin/session/revoke", {
          method: "POST",
          bearer: true,
          idem: true,
          body: { session_id },
        }),
      invites: () => call<InvitesResp>("/v1/admin/invites", { bearer: true }),
      vaults: () => call<VaultsResp>("/v1/admin/vaults", { bearer: true }),
      vault: (vault_id: string) =>
        call<VaultRow>("/v1/admin/vault", {
          bearer: true,
          query: { vault_id },
        }),
      objects: (q: {
        tag?: number;
        vault_id?: string;
        cursor?: number;
        limit?: number;
      }) =>
        call<ObjectsResp>("/v1/admin/objects", {
          bearer: true,
          query: q,
        }),
      relay: () => call<RelayResp>("/v1/admin/relay", { bearer: true }),
      keysets: (account_id?: string) =>
        call<KeysetsResp>("/v1/admin/keysets", {
          bearer: true,
          query: { account_id },
        }),
      config: () => call<ConfigResp>("/v1/admin/config", { bearer: true }),
      configPut: (body: ConfigPutReq) =>
        call<ConfigPutResp>("/v1/admin/config", {
          method: "PUT",
          bearer: true,
          idem: true,
          body,
        }),
      metrics: () => call<MetricsRaw>("/v1/admin/metrics", { bearer: true }),
      metricsSummary: () =>
        call<MetricsSummary>("/v1/admin/metrics/summary", { bearer: true }),
      health: () => call<HealthInfo>("/v1/admin/health", { bearer: true }),
      seqBump: (req: { by?: number; to?: number }) =>
        call<SeqBumpResp>("/v1/admin/seq-bump", {
          method: "POST",
          bearer: true,
          idem: true,
          body: req,
        }),
      migrations: () =>
        call<MigrationsResp>("/v1/admin/migrations", { bearer: true }),
      auditVerify: () =>
        call<AuditVerify>("/v1/admin/audit/verify", { bearer: true }),
    },

    // ── identity (Bearer: crypto + directory flows) ──
    identity: {
      accounts: () => call<AccountsResp>("/v1/accounts", { bearer: true }),
      deviceRevoke: (device_id: string) =>
        call<void>("/v1/session/device-revoke", {
          method: "POST",
          bearer: true,
          idem: true,
          body: { device_id },
        }),
      // v2: an invite carries per-space intents (join `space_id` at server-trusted
      // role member|admin) + optional selective vault intents. The caller must admin
      // every space it invites into (server enforces).
      issueInvite: (req: InviteIssueReq) =>
        call<InviteIssueResp>("/v1/invite", {
          method: "POST",
          bearer: true,
          idem: true,
          body: req,
        }),
      audit: (since_seq?: number, limit?: number) =>
        call<AuditResp>("/v1/audit", {
          bearer: true,
          query: { since_seq, limit },
        }),
      grants: (vault_id: string, key_epoch?: number) =>
        call<GrantsResp>("/v1/grants", {
          bearer: true,
          query: { vault_id, key_epoch },
        }),
      grantsPublish: (body: {
        manifest: string;
        grants: unknown[];
        new_epoch: number;
        revoke_epoch?: number;
      }) =>
        call<{ new_epoch: number; server_seq: number[] }>("/v1/grants/publish", {
          method: "POST",
          bearer: true,
          idem: true,
          body,
        }),
      // ── keyset (Path A publish; optional escrow enrollment) ──
      keysetPut: (body: KeysetPutReq) =>
        call<KeysetPutResp>("/v1/keyset", {
          method: "PUT",
          bearer: true,
          idem: true,
          body,
        }),
      // ── shared directory + vault-admin pending queue ──
      directory: () => call<DirectoryResp>("/v1/directory", { bearer: true }),
      pending: () => call<PendingResp>("/v1/pending", { bearer: true }),
      // ── auth (keyset unlock: challenge → sign → verify) ──
      challenge: (account_id: string, device_id: string, key_id: string) =>
        call<AuthChallenge>("/v1/auth/challenge", {
          method: "POST",
          body: { account_id, device_id, key_id },
        }),
      verify: (challenge: AuthChallenge, signature: string) =>
        call<VerifyResp>("/v1/auth/verify", {
          method: "POST",
          body: { challenge, signature },
        }),
    },

    // ── spaces (server-trusted groupings) ──
    spaces: {
      list: () => call<SpacesResp>("/v1/spaces", { bearer: true }),
      create: (name: string) =>
        call<CreateSpaceResp>("/v1/spaces", {
          method: "POST",
          bearer: true,
          idem: true,
          body: { name },
        }),
      addMember: (space_id: string, account_id: string, role: string) =>
        call<void>("/v1/spaces/members", {
          method: "POST",
          bearer: true,
          idem: true,
          body: { space_id, account_id, role },
        }),
    },

    // ── key-binding attestations ──
    attestations: {
      put: (account_id: string, blob: string, signature: string) =>
        call<void>("/v1/attestations", {
          method: "POST",
          bearer: true,
          idem: true,
          body: { account_id, blob, signature },
        }),
      list: (account_id: string) =>
        call<AttestationsResp>("/v1/attestations", {
          bearer: true,
          query: { account_id },
        }),
    },

    // ── instance-owner management (replaces admin/set) ──
    owner: {
      set: (account_id: string, is_owner: boolean) =>
        call<void>("/v1/owner/set", {
          method: "POST",
          bearer: true,
          idem: true,
          body: { account_id, is_owner },
        }),
    },
  };
}

export type ApiClient = ReturnType<typeof createClient>;
