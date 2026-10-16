import type { SessionInfo } from "../api";
import { ago, when } from "../format";
import { userHref } from "../router";

export function SessionTable({
  sessions,
  onRevoke,
  busy,
}: {
  sessions: SessionInfo[];
  onRevoke: (s: SessionInfo) => void;
  busy: string;
}) {
  if (sessions.length === 0) return <p className="muted">No live sessions.</p>;
  return (
    <table>
      <thead>
        <tr>
          <th>User</th>
          <th>Groups</th>
          <th>MFA</th>
          <th>Signed in</th>
          <th>Last seen</th>
          <th />
        </tr>
      </thead>
      <tbody>
        {sessions.map((s) => (
          <tr key={s.id}>
            <td>
              <a href={userHref(s.sub, s.user)}>{s.user}</a>
              {s.current && <span className="badge">you</span>}
              <div className="muted small">{s.email || s.sub}</div>
            </td>
            <td>{s.groups.join(", ") || <span className="muted">none</span>}</td>
            <td>{s.amr.length > 1 || s.amr.includes("mfa") ? s.amr.join("+") : <span className="muted">{s.amr.join("+") || "—"}</span>}</td>
            <td title={when(s.created)}>{ago(s.created)}</td>
            <td title={when(s.last_seen)}>{ago(s.last_seen)}</td>
            <td className="right">
              <button className="danger" disabled={busy === s.id} onClick={() => onRevoke(s)}>
                {busy === s.id ? "Revoking…" : "Revoke"}
              </button>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
