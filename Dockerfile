# syntax=docker/dockerfile:1
# Warden and the example upstream (docs/DECISIONS.md D25).
#   docker build --target warden .            (default)
#   docker build --target example-upstream .
# Base images are pinned to a version and a multi-arch digest; bump both
# together. Builds natively for amd64 and arm64.

FROM --platform=$BUILDPLATFORM node:24.21.0-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1 AS web
WORKDIR /src/web/admin
COPY web/admin/package.json web/admin/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/admin/ ./
RUN npm run build

FROM --platform=$BUILDPLATFORM golang:1.27.2-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS go
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/admin/dist ./web/admin/dist
ENV CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH
RUN go build -trimpath -ldflags="-s -w" -o /out/warden ./cmd/warden && \
    go build -trimpath -ldflags="-s -w" -o /out/example-upstream ./examples/upstream

# Static binaries on distroless: no shell, no package manager, non-root.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3 AS example-upstream
COPY --from=go /out/example-upstream /example-upstream
USER nonroot:nonroot
ENTRYPOINT ["/example-upstream"]

FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3 AS warden
COPY --from=go /out/warden /warden
USER nonroot:nonroot
EXPOSE 8443 8080
ENTRYPOINT ["/warden"]
