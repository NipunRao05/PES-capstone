FROM golang:1.21-alpine AS builder
WORKDIR /build

# kafka-go requires git for VCS metadata resolution
RUN apk add --no-cache git

# ── Dependency layer ──────────────────────────────────────────────────────────
COPY go.mod go.sum ./
RUN go mod download

# ── Source layer ──────────────────────────────────────────────────────────────
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
      -ldflags="-s -w" \
      -o mysqlproxy \
      ./cmd/proxy

# ── Runtime image ─────────────────────────────────────────────────────────────
FROM alpine:3.19
RUN apk add --no-cache ca-certificates wget
COPY --from=builder /build/mysqlproxy /mysqlproxy
EXPOSE 3306 9091
ENTRYPOINT ["/mysqlproxy"]