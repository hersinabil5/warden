.PHONY: dev-up dev-down dev-up-host dev-logs dev-check certs internal-ca run upstream build web showcase test lint fuzz

-include .env
export

# --env-file: compose would otherwise look for .env next to the compose file.
COMPOSE := docker compose --env-file .env -f deploy/docker-compose.yml
# Containers run as you, so the bind-mounted keys keep 0600 (D25).
export WARDEN_UID := $(shell id -u)
export WARDEN_GID := $(shell id -g)
MKCERT_ROOT := deploy/certs/mkcert-root.pem

# Everything in containers, Warden included; apps reachable only through it.
dev-up: $(MKCERT_ROOT)
	mkdir -p var
	$(COMPOSE) up -d --build --wait --wait-timeout 300

dev-down:
	$(COMPOSE) down

dev-logs:
	$(COMPOSE) logs -f warden

# Checks the running stack: Warden answers, the apps are unreachable except
# through it, nothing runs as root.
dev-check:
	./scripts/dev-check.sh

# For `make run`: the backing services only, with the apps published again.
dev-up-host:
	$(COMPOSE) -f deploy/docker-compose.host.yml up -d --wait --wait-timeout 300 keycloak redis whoami grafana

# The example upstream container fetches Warden's JWKS over TLS, so it needs
# the mkcert root that signed Warden's dev certificate.
$(MKCERT_ROOT):
	cp "$$(mkcert -CAROOT)/rootCA.pem" $@

DEV_CONFIG := config/warden.dev.yaml
SIGNING_KEY := deploy/certs/identity-signing-key.pem

# The TLS cert is safe to regenerate. The identity signing key is not: replacing
# it invalidates outstanding assertions, so rotation must be deliberate.
certs:
	umask 077 && mkdir -p deploy/certs
	umask 077 && mkcert -cert-file deploy/certs/warden.pem -key-file deploy/certs/warden-key.pem \
		auth.warden.localhost whoami.warden.localhost grafana.warden.localhost app.warden.localhost
	@if [ -e $(SIGNING_KEY) ]; then \
		echo "keeping existing $(SIGNING_KEY)"; \
	else \
		umask 077 && openssl ecparam -name prime256v1 -genkey -noout -out $(SIGNING_KEY) && \
		echo "generated $(SIGNING_KEY)"; \
	fi
	$(MAKE) internal-ca

# Dev internal CA for mTLS (Warden -> upstreams). Keeps an existing CA and
# reissues the leaf certificates (docs/DECISIONS.md D18).
internal-ca:
	umask 077 && go run ./cmd/devca -dir deploy/certs

run:
	@test -f $(DEV_CONFIG) || { \
		echo "missing $(DEV_CONFIG); create it with: cp config/warden.example.yaml $(DEV_CONFIG)" >&2; \
		exit 1; }
	go run ./cmd/warden -config $(DEV_CONFIG)

# examples/upstream on 127.0.0.1:9003 (route app.warden.localhost). It fetches
# Warden's JWKS over HTTPS, so it trusts mkcert's root for that.
upstream:
	go run ./examples/upstream -jwks-ca "$$(mkcert -CAROOT)/rootCA.pem"

# The admin dashboard is embedded into the binary (docs/DECISIONS.md D24), so
# build it first. npm ci installs exactly what package-lock.json pins.
build: web
	go build -o bin/warden ./cmd/warden

web:
	cd web/admin && npm ci --no-audit --no-fund && npm run build

# Static dashboard with sample data for Vercel (docs/SHOWCASE.md), in
# web/admin/dist-showcase. Never embedded in the binary.
showcase:
	cd web/admin && npm ci --no-audit --no-fund && npm run build:showcase

test:
	go test -race ./...

lint:
	go vet ./...
	golangci-lint run
	govulncheck ./...

# Go minimizes every new interesting input for up to 60s by default; on
# multi-KB paths that stalls a short run, so cap it.
FUZZ := -run=^$$ -fuzztime=30s -fuzzminimizetime=2s

fuzz:
	go test ./internal/pathnorm $(FUZZ) -fuzz=FuzzNormalize
	go test ./internal/policy $(FUZZ) -fuzz=FuzzEvaluate
	go test ./internal/authn $(FUZZ) -fuzz=FuzzReturnURL
