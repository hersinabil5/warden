import { useCallback, useEffect, useState } from "react";
import { listSessions, revokeSession, type SessionInfo } from "../api";
import { SessionTable } from "../components/SessionTable";
import { errorText } from "../format";

export function SessionsPage() {
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [total, setTotal] = useState(0);
  const [next, setNext] = useState<number | undefined>();
  const [filter, setFilter] = useState("");
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");

  const load = useCallback(() => {
    setError("");
    listSessions()
      .then((p) => {
        setSessions(p.sessions);
        setTotal(p.total);
        setNext(p.next_offset);
      })
      .catch((e: unknown) => setError(errorText(e)));
  }, []);
  useEffect(load, [load]);

  const more = () => {
    if (next === undefined) return;
    listSessions(next)
      .then((p) => {
        setSessions((s) => [...s, ...p.sessions]);
        setNext(p.next_offset);
      })
      .catch((e: unknown) => setError(errorText(e)));
  };

  const revoke = (s: SessionInfo) => {
    if (!window.confirm(`Revoke ${s.user}'s session${s.current ? " (your own)" : ""}?`)) return;
    setBusy(s.id);
    revokeSession(s.id)
      .then(() => setSessions((all) => all.filter((x) => x.id !== s.id)))
      .catch((e: unknown) => setError(errorText(e)))
      .finally(() => setBusy(""));
  };

  const q = filter.trim().toLowerCase();
  const shown = q ? sessions.filter((s) => [s.user, s.email, s.sub].some((v) => v.toLowerCase().includes(q))) : sessions;

  return (
    <section>
      <div className="bar">
        <h1>Live sessions</h1>
        <span className="muted">{total} total</span>
        <input
          type="search"
          placeholder="Find user…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          aria-label="Find user"
        />
        <button onClick={load}>Refresh</button>
      </div>
      {error && <p className="error">{error}</p>}
      <SessionTable sessions={shown} onRevoke={revoke} busy={busy} />
      {next !== undefined && (
        <button className="more" onClick={more}>
          Load more
        </button>
      )}
    </section>
  );
}
