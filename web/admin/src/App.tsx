import { useEffect, useState } from "react";
import { getMe, type Me } from "./api";
import { errorText } from "./format";
import { useLocation } from "./router";
import { AuditPage } from "./pages/Audit";
import { RoutesPage } from "./pages/Routes";
import { SessionsPage } from "./pages/Sessions";
import { UserPage } from "./pages/User";

const NAV = [
  ["sessions", "Sessions"],
  ["audit", "Audit log"],
  ["routes", "Routes"],
] as const;

export function App() {
  const [me, setMe] = useState<Me | null>(null);
  const [error, setError] = useState("");
  const loc = useLocation();

  useEffect(() => {
    getMe()
      .then(setMe)
      .catch((e: unknown) => setError(errorText(e)));
  }, []);

  return (
    <div className="shell">
      <header className="top">
        <span className="brand">Warden admin</span>
        <nav>
          {NAV.map(([page, label]) => (
            <a key={page} href={`#/${page}`} className={loc.page === page ? "active" : ""}>
              {label}
            </a>
          ))}
        </nav>
        {me && (
          <form className="who" method="post" action="/.warden/logout">
            <span>{me.user}</span>
            <button type="submit" className="link">
              Sign out
            </button>
          </form>
        )}
      </header>
      <main>
        {error && <p className="error">{error}</p>}
        {!me && !error && <p className="muted">Loading…</p>}
        {me && <Page loc={loc} me={me} />}
      </main>
    </div>
  );
}

function Page({ loc, me }: { loc: ReturnType<typeof useLocation>; me: Me }) {
  switch (loc.page) {
    case "audit":
      return <AuditPage initialUser={loc.params.get("user") ?? ""} initialHost={loc.params.get("host") ?? ""} />;
    case "routes":
      return <RoutesPage />;
    case "users":
      return <UserPage sub={loc.arg} name={loc.params.get("name") ?? ""} me={me} />;
    default:
      return <SessionsPage />;
  }
}
