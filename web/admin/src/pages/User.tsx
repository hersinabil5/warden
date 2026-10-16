import { useCallback, useEffect, useState } from "react";
import { listDecisions, revokeSession, revokeUser, userSessions, type Decision, type Me, type SessionInfo } from "../api";
import { DecisionTable } from "../components/DecisionTable";
import { SessionTable } from "../components/SessionTable";
import { errorText } from "../format";

export function UserPage({ sub, name, me }: { sub: string; name: string; me: Me }) {
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [decisions, setDecisions] = useState<Decision[]>([]);
  const [busy, setBusy] = useState("");
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const user = name || sessions[0]?.user || "";

  const load = useCallback(() => {
    setError("");
    userSessions(sub)
      .then((p) => setSessions(p.sessions))
      .catch((e: unknown) => setError(errorText(e)));
    if (name) {
      listDecisions({ user: name })
        .then((p) => setDecisions(p.decisions))
        .catch((e: unknown) => setError(errorText(e)));
    }
  }, [sub, name]);
  useEffect(load, [load]);

  const revokeOne = (s: SessionInfo) => {
    if (!window.confirm(`Revoke this session of ${s.user}?`)) return;
    setBusy(s.id);
    revokeSession(s.id)
      .then(() => setSessions((all) => all.filter((x) => x.id !== s.id)))
      .catch((e: unknown) => setError(errorText(e)))
      .finally(() => setBusy(""));
  };

  const revokeAll = () => {
    const self = sub === me.sub ? " This includes your own session." : "";
    if (!window.confirm(`Revoke every session of ${user || sub}?${self}`)) return;
    setBusy("all");
    revokeUser(sub)
      .then((r) => {
        setNotice(`Revoked ${r?.revoked ?? 0} session(s). Their next request goes to login.`);
        setSessions([]);
      })
      .catch((e: unknown) => setError(errorText(e)))
      .finally(() => setBusy(""));
  };

  return (
    <section>
      <div className="bar">
        <h1>{user || "User"}</h1>
        <span className="muted mono small">{sub}</span>
        <button className="danger" onClick={revokeAll} disabled={busy === "all" || sessions.length === 0}>
          {busy === "all" ? "Revoking…" : "Revoke all sessions"}
        </button>
      </div>
      {notice && <p className="notice">{notice}</p>}
      {error && <p className="error">{error}</p>}
      {sessions[0] && (
        <p className="small">
          Groups: {sessions[0].groups.join(", ") || "none"} · Email: {sessions[0].email || "none verified"}
        </p>
      )}
      <h2>Sessions</h2>
      <SessionTable sessions={sessions} onRevoke={revokeOne} busy={busy} />
      <h2>Recent access</h2>
      {name ? <DecisionTable decisions={decisions} /> : <p className="muted">Open this user from a session to see their access.</p>}
    </section>
  );
}
