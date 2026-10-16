import { useEffect, useState } from "react";

// Hash navigation: #/sessions, #/audit, #/routes, #/users/<sub>?name=<user>.
// No server routes are involved, so the server never needs a fallback.

export interface Location {
  page: string;
  arg: string;
  params: URLSearchParams;
}

function parse(): Location {
  const raw = window.location.hash.replace(/^#\/?/, "");
  const [path = "", query = ""] = raw.split("?", 2);
  const [page = "", ...rest] = path.split("/");
  return { page: page || "sessions", arg: decodeURIComponent(rest.join("/")), params: new URLSearchParams(query) };
}

export function useLocation(): Location {
  const [loc, setLoc] = useState(parse);
  useEffect(() => {
    const onChange = () => setLoc(parse());
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return loc;
}

export function userHref(sub: string, name: string): string {
  return `#/users/${encodeURIComponent(sub)}?name=${encodeURIComponent(name)}`;
}
