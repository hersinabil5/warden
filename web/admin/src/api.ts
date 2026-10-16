// Client for Warden's admin API (docs/DECISIONS.md D22). Same origin only;
// the session cookie is HttpOnly, so the browser sends it and this code
// never sees it. Mutations carry the session's CSRF token.

const API = "/.warden/api/";

export interface Me {
  user: string;
  sub: string;
  email: string;
  groups: string[];
  amr: string[];
  auth_time: string;
  session: string;
  csrf_token: string;
}

export interface SessionInfo {
  id: string;
  user: string;
  sub: string;
  email: string;
  groups: string[];
  amr: string[];
  auth_time: string;
  created: string;
  last_seen: string;
  current: boolean;
}

export interface SessionPage {
  sessions: SessionInfo[];
  total: number;
  next_offset?: number;
}

export interface Decision {
  seq: number;
  time: string;
  request_id: string;
  user: string;
  session: string;
  host: string;
  method: string;
  path: string;
  decision: "allow" | "deny";
  rule: string;
  reason: string;
  latency_ms: number;
  status: number;
}

export interface DecisionPage {
  decisions: Decision[];
  next_before?: number;
}

export interface Rule {
  authenticated?: boolean;
  users?: string[];
  groups?: string[];
  email_domains?: string[];
  require_mfa_within?: string;
}

export interface Route {
  host: string;
  upstream: string;
  upstream_tls: boolean;
  policy: {
    allow: Rule[];
    paths: { prefix: string; allow: Rule[] }[];
    case_insensitive_paths: boolean;
  };
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly requestId: string,
  ) {
    super(`request failed (${status})${requestId ? `, request ID ${requestId}` : ""}`);
  }
}

async function check(res: Response): Promise<Response> {
  if (!res.ok) {
    let requestId = res.headers.get("X-Request-ID") ?? "";
    try {
      const body = (await res.json()) as { request_id?: string };
      requestId = body.request_id ?? requestId;
    } catch {
      // not JSON; keep the header's ID
    }
    throw new ApiError(res.status, requestId);
  }
  return res;
}

async function get<T>(path: string, params: Record<string, string | number | undefined> = {}): Promise<T> {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== "") q.set(k, String(v));
  }
  const url = API + path + (q.size ? `?${q}` : "");
  const res = await check(await fetch(url, { credentials: "same-origin", cache: "no-store" }));
  return (await res.json()) as T;
}

let csrfToken = "";

async function post<T>(path: string, body: unknown): Promise<T | null> {
  const res = await check(
    await fetch(API + path, {
      method: "POST",
      credentials: "same-origin",
      cache: "no-store",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
      body: JSON.stringify(body),
    }),
  );
  return res.status === 204 ? null : ((await res.json()) as T);
}

export async function getMe(): Promise<Me> {
  const me = await get<Me>("me");
  csrfToken = me.csrf_token;
  return me;
}

export const listSessions = (offset = 0) => get<SessionPage>("sessions", { offset, limit: 100 });
export const userSessions = (sub: string) => get<SessionPage>("sessions", { sub });
export const listDecisions = (f: { user?: string; host?: string; decision?: string; before?: number }) =>
  get<DecisionPage>("decisions", { ...f, limit: 100 });
export const listRoutes = () => get<{ routes: Route[] }>("routes");
export const revokeSession = (id: string) => post<null>("sessions/revoke", { id });
export const revokeUser = (sub: string) => post<{ revoked: number }>("users/revoke", { sub });
