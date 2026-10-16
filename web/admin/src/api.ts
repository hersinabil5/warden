// Client for Warden's admin API (docs/DECISIONS.md D22). Same origin only;
// the session cookie is HttpOnly, so the browser sends it and this code
// never sees it.

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

export async function get<T>(path: string, params: Record<string, string> = {}): Promise<T> {
  const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v !== ""));
  const url = API + path + (q.size ? `?${q}` : "");
  const res = await check(await fetch(url, { credentials: "same-origin", cache: "no-store" }));
  return (await res.json()) as T;
}

export const getMe = () => get<Me>("me");
