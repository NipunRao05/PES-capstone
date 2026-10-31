FROM golang:1.26-alpine@sha256:a2012b4a1d1f9f7e9f44e0d39b805a901e856b1dd80b4e6ee4338db547050308 AS builder
WORKDIR /app

# ── Dependency layer ──────────────────────────────────────────────────────────
COPY go.mod go.sum ./
RUN go mod download

# ── Source layer ──────────────────────────────────────────────────────────────
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
      -ldflags="-s -w" \
      -o pgproxy \
      ./cmd/proxy

# ── Runtime image ─────────────────────────────────────────────────────────────
FROM alpine:3.23@sha256:ff7f0c727dd796aa36787bfcd9a64bf35a6ce72a73451b3359fde849b6703d63
RUN apk add --no-cache iptables=1.8.11-r1 iproute2=6.17.0-r0 util-linux=2.41.6-r1 ca-certificates=20261020-r0 tzdata=2026e-r0 wget=1.25.0-r2
WORKDIR /app
COPY --from=builder /app/pgproxy .
EXPOSE 5432 9090
ENTRYPOINT ["./pgproxy"]