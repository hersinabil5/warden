.PHONY: dev-up dev-down certs run build test lint fuzz

-include .env
export

dev-up:
	docker compose -f deploy/docker-compose.yml up -d

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

run:
	@test -f $(DEV_CONFIG) || { \
		echo "missing $(DEV_CONFIG); create it with: cp config/warden.example.yaml $(DEV_CONFIG)" >&2; \
		exit 1; }
	go run ./cmd/warden -config $(DEV_CONFIG)

build:
	go build -o bin/warden ./cmd/warden

test:
	go test -race ./...

lint:
	go vet ./...
	golangci-lint run
	govulncheck ./...

fuzz:
	go test ./internal/pathnorm -run=^$$ -fuzz=Fuzz -fuzztime=30s
	go test ./internal/policy -run=^$$ -fuzz=Fuzz -fuzztime=30s
