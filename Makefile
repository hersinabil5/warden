.PHONY: dev-up dev-down certs internal-ca run upstream build test lint fuzz

-include .env
export

dev-up:
	docker compose -f deploy/docker-compose.yml up -d --wait --wait-timeout 180

dev-down:
	docker compose -f deploy/docker-compose.yml down

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

build:
	go build -o bin/warden ./cmd/warden

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
