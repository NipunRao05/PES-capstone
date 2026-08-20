FROM golang:1.22-alpine AS builder
WORKDIR /build

RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o scaling-agent \
    ./cmd/agent

FROM alpine:3.19
RUN apk add --no-cache ca-certificates wget
COPY --from=builder /build/scaling-agent /scaling-agent
EXPOSE 8080
ENTRYPOINT ["/scaling-agent"]
