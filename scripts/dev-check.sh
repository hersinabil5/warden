#!/usr/bin/env bash
# Checks the running container stack (make dev-up) against M7's isolation
# guarantees (docs/DECISIONS.md D25). Exits non-zero on the first failure.
set -euo pipefail

compose=(docker compose --env-file .env -f deploy/docker-compose.yml)
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok:   $*"; }

# 1. Warden answers on its published port.
code=$(curl -sk -o /dev/null -w '%{http_code}' https://auth.warden.localhost:8443/.warden/healthz) || true
[[ $code == 200 ]] || fail "Warden healthz returned $code"
ok "Warden is up on 127.0.0.1:8443"

# 2. A route without a session is sent to login, not to the app.
loc=$(curl -sk -o /dev/null -w '%{http_code} %{redirect_url}' https://whoami.warden.localhost:8443/) || true
[[ $loc == "302 "*"/.warden/login"* ]] || fail "unauthenticated request was not redirected to login: $loc"
ok "unauthenticated requests go to login"

# 3. The apps and Redis are unreachable from the host (the old dev ports).
for port in 9001 9002 9003 6379; do
  if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
    fail "something listens on 127.0.0.1:$port; the apps must be reachable only through Warden"
  fi
done
ok "apps and Redis are not reachable from the host"

# 4. Only Warden and Keycloak publish ports, and only on 127.0.0.1.
for svc in whoami grafana example-upstream redis; do
  published=$(docker inspect -f '{{range $p, $b := .NetworkSettings.Ports}}{{if $b}}{{$p}} {{end}}{{end}}' "$("${compose[@]}" ps -q "$svc")")
  [[ -z $published ]] || fail "$svc publishes $published"
done
for svc in warden keycloak; do
  binds=$(docker inspect -f '{{range $p, $b := .NetworkSettings.Ports}}{{range $b}}{{.HostIp}} {{end}}{{end}}' "$("${compose[@]}" ps -q "$svc")")
  for ip in $binds; do [[ $ip == 127.0.0.1 ]] || fail "$svc publishes on $ip"; done
done
ok "only Warden and Keycloak publish ports, on 127.0.0.1 only"

# 5. The app network has no route out, and Warden's containers don't run as root.
[[ $(docker network inspect -f '{{.Internal}}' warden-dev_apps) == true ]] || fail "the apps network is not internal"
for svc in warden example-upstream; do
  user=$(docker inspect -f '{{.Config.User}}' "$("${compose[@]}" ps -q "$svc")")
  [[ -n $user && $user != 0* && $user != root* ]] || fail "$svc runs as '$user'"
done
ok "apps network is internal; Warden and the example app run as non-root"

echo "all checks passed"
