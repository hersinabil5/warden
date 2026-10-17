// Transport to Warden's admin API (docs/DECISIONS.md D22). Same origin only;
// the session cookie is HttpOnly, so the browser sends it and this code
// never sees it. Mutations carry the session's CSRF token.
//
// The showcase build replaces this module with showcase/backend.ts
// (vite.config.ts, D31); both export the same functions.

import { ApiError } from "./errors";

const API = "/.warden/api/";

export type Params = Record<string, string | number | undefined>;

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

export async function get<T>(path: string, params: Params = {}): Promise<T> {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== "") q.set(k, String(v));
  }
  const url = API + path + (q.size ? `?${q}` : "");
  const res = await check(await fetch(url, { credentials: "same-origin", cache: "no-store" }));
  return (await res.json()) as T;
}

let csrfToken = "";

export function setCsrfToken(token: string): void {
  csrfToken = token;
}

export async function post<T>(path: string, body: unknown): Promise<T | null> {
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
