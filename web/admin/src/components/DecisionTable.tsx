import type { Decision } from "../api";
import { when } from "../format";

export function DecisionTable({ decisions }: { decisions: Decision[] }) {
  if (decisions.length === 0) return <p className="muted">No matching decisions.</p>;
  return (
    <table>
      <thead>
        <tr>
          <th>Time</th>
          <th>User</th>
          <th>Request</th>
          <th>Decision</th>
          <th>Rule / reason</th>
          <th className="right">Status</th>
        </tr>
      </thead>
      <tbody>
        {decisions.map((d) => (
          <tr key={d.seq}>
            <td className="small">{when(d.time)}</td>
            <td>{d.user || <span className="muted">anonymous</span>}</td>
            <td className="mono small">
              {d.method} {d.host}
              {d.path}
            </td>
            <td>
              <span className={`pill ${d.decision}`}>{d.decision}</span>
            </td>
            <td className="small">
              {d.rule && <span className="mono">{d.rule}</span>} {d.reason}
            </td>
            <td className="right mono small">{d.status}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
