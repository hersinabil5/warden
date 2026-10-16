import { useEffect, useState } from "react";
import { listRoutes, type Route, type Rule } from "../api";
import { errorText } from "../format";

function RuleText({ rule }: { rule: Rule }) {
  const parts: string[] = [];
  if (rule.authenticated) parts.push("any signed-in user");
  if (rule.users) parts.push(`users ${rule.users.join(", ")}`);
  if (rule.groups) parts.push(`groups ${rule.groups.join(", ")}`);
  if (rule.email_domains) parts.push(`email @${rule.email_domains.join(", @")}`);
  if (rule.require_mfa_within) parts.push(`MFA within ${rule.require_mfa_within}`);
  return <li>{parts.join(" and ")}</li>;
}

function Rules({ rules }: { rules: Rule[] }) {
  return (
    <ul className="rules">
      {rules.map((r, i) => (
        <RuleText key={i} rule={r} />
      ))}
    </ul>
  );
}

export function RoutesPage() {
  const [routes, setRoutes] = useState<Route[]>([]);
  const [error, setError] = useState("");
  useEffect(() => {
    listRoutes()
      .then((r) => setRoutes(r.routes))
      .catch((e: unknown) => setError(errorText(e)));
  }, []);

  return (
    <section>
      <div className="bar">
        <h1>Routes</h1>
        <span className="muted">Read-only; edit the config file and restart to change.</span>
      </div>
      {error && <p className="error">{error}</p>}
      {routes.map((r) => (
        <article key={r.host} className="card">
          <h2>
            {r.host} <span className="muted small mono">→ {r.upstream}</span>
            {r.upstream_tls && <span className="badge">mTLS</span>}
          </h2>
          <p className="small muted">Any rule allows (rules are ORed; conditions in a rule are ANDed). Everything else is denied.</p>
          <h3>All paths</h3>
          <Rules rules={r.policy.allow} />
          {r.policy.paths.map((p) => (
            <div key={p.prefix}>
              <h3>
                <span className="mono">{p.prefix}</span> (replaces the rules above)
              </h3>
              <Rules rules={p.allow} />
            </div>
          ))}
          {r.policy.case_insensitive_paths && <p className="small muted">Path prefixes match ignoring case.</p>}
        </article>
      ))}
    </section>
  );
}
