# HostingInside WAF: one image with both binaries (engine and manager). The
# console is built first and embedded into the manager.

FROM node:22-bookworm-slim AS console
WORKDIR /src/console
COPY console/package.json console/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY console/ ./
RUN npm run build

FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=console /src/manager/console/dist/ ./manager/console/dist/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/hi-waf ./cmd/hi-waf \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/manager ./cmd/manager

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tzdata curl \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/ /usr/local/bin/
# Caddy keeps certificates, its CA and the autosaved config (for --resume)
# under the data volume.
ENV XDG_DATA_HOME=/data/caddy XDG_CONFIG_HOME=/data/caddy-config
VOLUME /data
WORKDIR /data
