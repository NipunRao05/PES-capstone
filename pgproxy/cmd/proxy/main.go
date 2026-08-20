package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/pgproxy/internal/connection"
)

func main() {
	logLevel := slog.LevelInfo
	if os.Getenv("LOG_LEVEL") == "debug" {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))
	slog.SetDefault(logger)

	cfg := connection.Config{
		ListenAddr:  getEnv("PROXY_LISTEN_ADDR", "0.0.0.0:5432"),
		BackendAddr: getEnv("PG_BACKEND_ADDR", "localhost:5432"),
		HTTPAddr:    getEnv("HTTP_ADDR", "0.0.0.0:9090"), // Fix 9: health+metrics

		// Fix 6: graceful shutdown timeout
		ShutdownTimeout: getDuration("SHUTDOWN_TIMEOUT", 30*time.Second),

		// Fix 3: backend health check interval
		BackendPingInterval: getDuration("BACKEND_PING_INTERVAL", 15*time.Second),

		// Tuning
		MaxConnections: getInt("MAX_CONNECTIONS", 10000),
		DialTimeout:    getDuration("DIAL_TIMEOUT", 10*time.Second),

		KafkaBrokers:      splitBrokers(getEnv("KAFKA_BROKERS", "")),
		KafkaTopic:        getEnv("KAFKA_TOPIC", "pg-query-events"),
		KafkaDedupTopic:   getEnv("KAFKA_DEDUP_TOPIC", "pg-query-dedup"),
		KafkaSessionTopic: getEnv("KAFKA_SESSION_TOPIC", "pg-session-events"),
	}

	mgr, err := connection.NewManager(cfg, logger)
	if err != nil {
		logger.Error("failed to create connection manager", "error", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		logger.Info("received shutdown signal", "signal", sig)
		cancel()
	}()

	logger.Info("starting PostgreSQL proxy",
		"listen", cfg.ListenAddr,
		"backend", cfg.BackendAddr,
		"http", cfg.HTTPAddr,
		"shutdown_timeout", cfg.ShutdownTimeout,
	)

	if err := mgr.ListenAndServe(ctx); err != nil {
		logger.Error("proxy exited with error", "error", err)
		os.Exit(1)
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}

func getInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n := 0
	for _, c := range v {
		if c < '0' || c > '9' {
			return fallback
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func splitBrokers(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}