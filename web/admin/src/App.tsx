import { useEffect, useState } from "react";
import { ApiError, getMe, type Me } from "./api";

export function App() {
  const [me, setMe] = useState<Me | null>(null);
  const [error, setError] = useState<string>("");

  useEffect(() => {
    getMe()
      .then(setMe)
      .catch((e: unknown) => setError(e instanceof ApiError ? e.message : "could not reach Warden"));
  }, []);

  return (
    <div className="shell">
      <header className="top">
        <span className="brand">Warden admin</span>
        {me && <span className="who">{me.user}</span>}
      </header>
      <main>
        {error && <p className="error">{error}</p>}
        {!me && !error && <p className="muted">Loading…</p>}
        {me && <p>Signed in as {me.user}.</p>}
      </main>
    </div>
  );
}
