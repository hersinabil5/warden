.PHONY: dev-up dev-down certs run build test lint fuzz

-include .env
export

dev-up:
	docker compose -f deploy/docker-compose.yml up -d

dev-down:
	docker compose -f deploy/docker-compose.yml down

certs:
	mkdir -p deploy/certs
	mkcert -cert-file deploy/certs/warden.pem -key-file deploy/certs/warden-key.pem \
		auth.warden.localhost whoami.warden.localhost grafana.warden.localhost app.warden.localhost
	openssl ecparam -name prime256v1 -genkey -noout -out deploy/certs/identity-signing-key.pem

run:
	go run ./cmd/warden -config config/warden.dev.yaml

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
