import { useCallback, useEffect, useState } from "react";
import { listDecisions, type Decision } from "../api";
import { DecisionTable } from "../components/DecisionTable";
import { errorText } from "../format";

export function AuditPage({ initialUser, initialHost }: { initialUser: string; initialHost: string }) {
  const [user, setUser] = useState(initialUser);
  const [host, setHost] = useState(initialHost);
  const [decision, setDecision] = useState("");
  const [rows, setRows] = useState<Decision[]>([]);
  const [next, setNext] = useState<number | undefined>();
  const [error, setError] = useState("");

  const search = useCallback(() => {
    setError("");
    listDecisions({ user, host, decision })
      .then((p) => {
        setRows(p.decisions);
        setNext(p.next_before);
      })
      .catch((e: unknown) => setError(errorText(e)));
  }, [user, host, decision]);
  // Search on load and when the decision filter changes; the text filters
  // apply on submit.
  useEffect(() => search(), [decision]);

  const more = () => {
    if (next === undefined) return;
    listDecisions({ user, host, decision, before: next })
      .then((p) => {
        setRows((r) => [...r, ...p.decisions]);
        setNext(p.next_before);
      })
      .catch((e: unknown) => setError(errorText(e)));
  };

  return (
    <section>
      <form
        className="bar"
        onSubmit={(e) => {
          e.preventDefault();
          search();
        }}
      >
        <h1>Audit log</h1>
        <input placeholder="User" value={user} onChange={(e) => setUser(e.target.value)} aria-label="User" />
        <input placeholder="Host" value={host} onChange={(e) => setHost(e.target.value)} aria-label="Host" />
        <select value={decision} onChange={(e) => setDecision(e.target.value)} aria-label="Decision">
          <option value="">Allow and deny</option>
          <option value="allow">Allow</option>
          <option value="deny">Deny</option>
        </select>
        <button type="submit">Search</button>
      </form>
      <p className="muted small">The most recent 10,000 decisions since Warden started. The full record is the audit file.</p>
      {error && <p className="error">{error}</p>}
      <DecisionTable decisions={rows} />
      {next !== undefined && (
        <button className="more" onClick={more}>
          Load older
        </button>
      )}
    </section>
  );
}
