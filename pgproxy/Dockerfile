FROM golang:1.21-alpine AS builder
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
FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata wget
WORKDIR /app
COPY --from=builder /app/pgproxy .
EXPOSE 5432 9090
ENTRYPOINT ["./pgproxy"]