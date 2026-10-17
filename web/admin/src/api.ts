// Warden's admin API: types and calls. The transport is ./backend (the real
// API) or, in the showcase build, sample data (docs/DECISIONS.md D31).

import { get, post, setCsrfToken } from "./backend";

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

export { ApiError } from "./errors";

export async function getMe(): Promise<Me> {
  const me = await get<Me>("me");
  setCsrfToken(me.csrf_token);
  return me;
}

export const listSessions = (offset = 0) => get<SessionPage>("sessions", { offset, limit: 100 });
export const userSessions = (sub: string) => get<SessionPage>("sessions", { sub });
export const listDecisions = (f: { user?: string; host?: string; decision?: string; before?: number }) =>
  get<DecisionPage>("decisions", { ...f, limit: 100 });
export const listRoutes = () => get<{ routes: Route[] }>("routes");
export const revokeSession = (id: string) => post<null>("sessions/revoke", { id });
export const revokeUser = (sub: string) => post<{ revoked: number }>("users/revoke", { sub });
