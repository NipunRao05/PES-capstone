package main

import (
"context"
"log/slog"
"os"
"os/signal"
"strconv"
"strings"
"syscall"
"time"

"github.com/scalingagent/internal/consumer"
"github.com/scalingagent/internal/metriccollector"
"github.com/scalingagent/internal/metrics"
"github.com/scalingagent/internal/scaler"
"github.com/scalingagent/internal/scorer"
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

brokers := splitBrokers(getEnv("KAFKA_BROKERS", "redpanda:9092"))
httpAddr := getEnv("HTTP_ADDR", "0.0.0.0:8080")

logger.Info("starting scaling agent",
"brokers", brokers,
"http_addr", httpAddr,
)

cons := consumer.New(consumer.Config{
Brokers:              brokers,
TopicMitreEvents:     getEnv("TOPIC_MITRE_EVENTS", "mitre-events"),
TopicSessionProfiles: getEnv("TOPIC_SESSION_PROFILES", "session-profiles"),
GroupID:              getEnv("CONSUMER_GROUP", "scaling-agent"),
DialTimeout:          getDuration("DIAL_TIMEOUT", 10*time.Second),
StartOffset:          consumer.ParseStartOffset(getEnv("CONSUMER_START_OFFSET", "latest")),
}, logger)

sc := scaler.New(logger)
metricsSrv := metrics.New(httpAddr, sc, logger)

metricCollector := metriccollector.New(metriccollector.Config{
Enabled:                  getBool("METRIC_SCALING_ENABLED", true),
PrometheusURL:            getEnv("PROMETHEUS_URL", "http://prometheus:9090"),
PollInterval:             getDuration("METRIC_POLL_INTERVAL", 15*time.Second),
ActiveConnectionCapacity: getFloat("METRIC_ACTIVE_CONNECTION_CAPACITY", 20),
ConnectionRateCapacity:   getFloat("METRIC_CONNECTION_RATE_CAPACITY", 0.2),
BackendUnhealthyPressure: getFloat("METRIC_BACKEND_UNHEALTHY_PRESSURE", 0.7),
}, logger)

ctx, cancel := context.WithCancel(context.Background())
defer cancel()

sigCh := make(chan os.Signal, 1)
signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
go func() {
sig := <-sigCh
logger.Info("received shutdown signal", "signal", sig)
cancel()
}()

cons.Start(ctx)

signals := make(chan scorer.SessionSignal, 10000)

go func() {
for {
select {
case <-ctx.Done():
return
case sig, ok := <-cons.Signals():
if !ok {
return
}
select {
case signals <- sig:
case <-ctx.Done():
return
}
}
}
}()

go metricCollector.Run(ctx, signals)

go func() {
if err := metricsSrv.ListenAndServe(); err != nil {
logger.Warn("metrics server stopped", "error", err)
}
}()

sc.Run(ctx, signals)

metricsSrv.Shutdown()
logger.Info("scaling agent stopped")
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

func getBool(key string, fallback bool) bool {
v := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
if v == "" {
return fallback
}
switch v {
case "1", "true", "yes", "y", "on":
return true
case "0", "false", "no", "n", "off":
return false
default:
return fallback
}
}

func getFloat(key string, fallback float64) float64 {
v := strings.TrimSpace(os.Getenv(key))
if v == "" {
return fallback
}
f, err := strconv.ParseFloat(v, 64)
if err != nil {
return fallback
}
return f
}

func splitBrokers(s string) []string {
if s == "" {
return []string{"localhost:9092"}
}
return strings.Split(s, ",")
}
