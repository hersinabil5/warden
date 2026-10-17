// Showcase transport: answers the admin API's calls from sample data held in
// memory, so the dashboard runs as a static site with no Warden behind it
// (docs/DECISIONS.md D31). Only the showcase build includes this module.
// Revocations change the in-memory data; a reload starts over.
//
// Hosts use the reserved .example domain (RFC 2606): nothing here names a
// real organization.

import type { Decision, Me, Route, SessionInfo } from "../api";
import { ApiError } from "../errors";

export type Params = Record<string, string | number | undefined>;

const now = Date.now();
const minutes = (m: number) => new Date(now - m * 60_000).toISOString();

const DOMAIN = "corp.example";
const WHOAMI = `whoami.${DOMAIN}`;
const GRAFANA = `grafana.${DOMAIN}`;
const APP = `app.${DOMAIN}`;

function hex(n: number, seed: number): string {
  let out = "";
  let x = seed * 2654435761;
  while (out.length < n) {
    x = (x * 1103515245 + 12345) >>> 0;
    out += x.toString(16).padStart(8, "0");
  }
  return out.slice(0, n);
}

const users = {
  alice: { sub: "7c1e4a52-alice", email: `alice@${DOMAIN}`, groups: ["admins", "sre"] },
  bob: { sub: "3b9d07f1-bob", email: `bob@${DOMAIN}`, groups: ["dev"] },
  carol: { sub: "e52a6c90-carol", email: `carol@${DOMAIN}`, groups: ["sre"] },
};
type User = keyof typeof users;

function session(user: User, seed: number, created: number, lastSeen: number, mfa: boolean): SessionInfo {
  const u = users[user];
  return {
    id: hex(64, seed),
    user,
    sub: u.sub,
    email: u.email,
    groups: u.groups,
    amr: mfa ? ["pwd", "otp"] : ["pwd"],
    auth_time: minutes(created),
    created: minutes(created),
    last_seen: minutes(lastSeen),
    current: false,
  };
}

let sessions: SessionInfo[] = [
  { ...session("alice", 1, 6, 0, true), current: true },
  session("bob", 2, 48, 1, false),
  session("bob", 3, 190, 22, false),
  session("carol", 4, 75, 4, true),
];

const me: Me = {
  user: "alice",
  sub: users.alice.sub,
  email: users.alice.email,
  groups: users.alice.groups,
  amr: ["pwd", "otp"],
  auth_time: minutes(6),
  session: hex(12, 1),
  csrf_token: "showcase",
};

const MFA = "10m";
const routes: Route[] = [
  {
    host: WHOAMI,
    upstream: "http://whoami:80",
    upstream_tls: false,
    policy: { allow: [{ authenticated: true }], paths: [], case_insensitive_paths: false },
  },
  {
    host: GRAFANA,
    upstream: "http://grafana:3000",
    upstream_tls: false,
    policy: {
      allow: [{ groups: ["sre", "admins"] }],
      paths: [{ prefix: "/admin", allow: [{ groups: ["admins"], require_mfa_within: MFA }] }],
      case_insensitive_paths: false,
    },
  },
  {
    host: APP,
    upstream: "https://example-upstream:9003",
    upstream_tls: true,
    policy: { allow: [{ authenticated: true }], paths: [], case_insensitive_paths: false },
  },
];

// What happened, newest last: [minutes ago, user, host, method, path, allow, rule, reason, status, ms].
type Row = [number, User | "", string, string, string, boolean, string, string, number, number];
const story: Row[] = [
  [182, "bob", WHOAMI, "GET", "/", true, "allow[0]", "matched", 200, 3.1],
  [181, "bob", GRAFANA, "GET", "/", false, "allow", "no allow rule matched (allow[0]: not in a listed group)", 403, 1.2],
  [180, "bob", GRAFANA, "GET", "/d/home", false, "allow", "no allow rule matched (allow[0]: not in a listed group)", 403, 0.9],
  [176, "", GRAFANA, "GET", "/admin/users", false, "", "unauthenticated", 302, 0.4],
  [175, "", GRAFANA, "GET", "/%2e%2e/admin", false, "", "invalid path", 400, 0.2],
  [175, "", GRAFANA, "GET", "/admin%2Fusers", false, "", "invalid path", 400, 0.2],
  [174, "", GRAFANA, "GET", "/admin\\users", false, "", "invalid path", 400, 0.2],
  [174, "", GRAFANA, "GET", "/admin%00", false, "", "invalid path", 400, 0.2],
  [120, "carol", GRAFANA, "GET", "/", true, "allow[0]", "matched", 200, 18.4],
  [119, "carol", GRAFANA, "GET", "/api/dashboards/home", true, "allow[0]", "matched", 200, 22.7],
  [118, "carol", GRAFANA, "GET", "/admin", false, "paths[/admin]", "no allow rule matched (paths[/admin].allow[0]: not in a listed group)", 403, 0.8],
  [74, "carol", WHOAMI, "GET", "/", true, "allow[0]", "matched", 200, 2.6],
  [73, "carol", APP, "GET", "/", true, "allow[0]", "matched", 200, 5.9],
  [61, "", WHOAMI, "GET", "/", false, "", "unsupported upgrade", 400, 0.3],
  [47, "bob", WHOAMI, "GET", "/", true, "allow[0]", "matched", 200, 2.9],
  [46, "bob", APP, "GET", "/", true, "allow[0]", "matched", 200, 6.3],
  [46, "bob", WHOAMI, "GET", "/echo", true, "allow[0]", "matched", 101, 31_204],
  [40, "bob", GRAFANA, "GET", "/admin", false, "paths[/admin]", "no allow rule matched (paths[/admin].allow[0]: not in a listed group)", 403, 0.7],
  [39, "bob", GRAFANA, "GET", "/ADMIN", false, "allow", "no allow rule matched (allow[0]: not in a listed group)", 403, 0.7],
  [33, "bob", WHOAMI, "GET", "/echo", false, "", "cross-origin websocket", 403, 0.3],
  [21, "bob", WHOAMI, "GET", "/headers", true, "allow[0]", "matched", 200, 2.4],
  [9, "alice", GRAFANA, "GET", "/", true, "allow[0]", "matched", 200, 16.2],
  [8, "alice", GRAFANA, "GET", "/admin", false, "paths[/admin]", "step-up required", 302, 0.9],
  [6, "alice", GRAFANA, "GET", "/admin", true, "paths[/admin].allow[0]", "matched", 200, 24.1],
  [5, "alice", GRAFANA, "GET", "/admin/users", true, "paths[/admin].allow[0]", "matched", 200, 19.8],
  [4, "carol", GRAFANA, "GET", "/d/latency", true, "allow[0]", "matched", 200, 27.5],
  [3, "alice", WHOAMI, "GET", "/", true, "allow[0]", "matched", 200, 2.2],
  [2, "", WHOAMI, "GET", "/", false, "", "unauthenticated", 302, 0.4],
  [1, "bob", WHOAMI, "GET", "/", true, "allow[0]", "matched", 200, 2.7],
  [1, "alice", APP, "GET", "/", true, "allow[0]", "matched", 200, 6.1],
];

const sessionOf = (user: User | ""): string => {
  const s = sessions.find((x) => x.user === user);
  return s ? s.id.slice(0, 12) : "";
};

const decisions: Decision[] = story.map(([ago, user, host, method, path, allow, rule, reason, status, ms], i) => ({
  seq: 1000 + i,
  time: minutes(ago),
  request_id: hex(26, 100 + i).toUpperCase(),
  user,
  session: sessionOf(user),
  host,
  method,
  path,
  decision: allow ? "allow" : "deny",
  rule,
  reason,
  latency_ms: ms,
  status,
}));
let nextSeq = 1000 + story.length;

function record(path: string, reason: string) {
  decisions.push({
    seq: nextSeq++,
    time: new Date().toISOString(),
    request_id: hex(26, nextSeq).toUpperCase(),
    user: "alice",
    session: me.session,
    host: `auth.${DOMAIN}`,
    method: "POST",
    path,
    decision: "allow",
    rule: "admin.allow[0]",
    reason,
    latency_ms: 1.4,
    status: 200,
  });
}

const pause = () => new Promise((r) => setTimeout(r, 120));
const str = (v: string | number | undefined) => (v === undefined ? "" : String(v));

export function setCsrfToken(): void {}

export async function get<T>(path: string, params: Params = {}): Promise<T> {
  await pause();
  switch (path) {
    case "me":
      return me as T;
    case "routes":
      return { routes } as T;
    case "sessions": {
      const sub = str(params.sub);
      const list = sub ? sessions.filter((s) => s.sub === sub) : sessions;
      return { sessions: list, total: list.length } as T;
    }
    case "decisions": {
      const user = str(params.user);
      const host = str(params.host);
      const decision = str(params.decision);
      const before = Number(params.before ?? 0);
      const limit = Number(params.limit ?? 50);
      const all = decisions
        .filter((d) => (!user || d.user === user) && (!host || d.host === host) && (!decision || d.decision === decision))
        .filter((d) => !before || d.seq < before)
        .sort((a, b) => b.seq - a.seq);
      const page = all.slice(0, limit);
      const last = page.at(-1);
      return (all.length > limit && last ? { decisions: page, next_before: last.seq } : { decisions: page }) as T;
    }
  }
  throw new ApiError(404, "");
}

export async function post<T>(path: string, body: unknown): Promise<T | null> {
  await pause();
  const b = body as { id?: string; sub?: string };
  switch (path) {
    case "sessions/revoke": {
      const before = sessions.length;
      sessions = sessions.filter((s) => s.id !== b.id);
      if (sessions.length === before) throw new ApiError(404, "");
      record("/.warden/api/sessions/revoke", "matched");
      return null;
    }
    case "users/revoke": {
      const before = sessions.length;
      sessions = sessions.filter((s) => s.sub !== b.sub);
      record("/.warden/api/users/revoke", "matched");
      return { revoked: before - sessions.length } as T;
    }
  }
  throw new ApiError(404, "");
}
