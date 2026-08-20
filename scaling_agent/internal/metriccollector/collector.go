package metriccollector

import (
"context"
"encoding/json"
"fmt"
"log/slog"
"math"
"net/http"
"net/url"
"strconv"
"strings"
"time"

"github.com/scalingagent/internal/scorer"
)

type Config struct {
Enabled                  bool
PrometheusURL            string
PollInterval             time.Duration
ActiveConnectionCapacity float64
ConnectionRateCapacity   float64
BackendUnhealthyPressure float64
}

type Collector struct {
cfg    Config
logger *slog.Logger
client *http.Client
}

type promResponse struct {
Status string `json:"status"`
Data   struct {
Result []struct {
Value []json.RawMessage `json:"value"`
} `json:"result"`
} `json:"data"`
}

func New(cfg Config, logger *slog.Logger) *Collector {
if cfg.PrometheusURL == "" {
cfg.PrometheusURL = "http://prometheus:9090"
}
if cfg.PollInterval <= 0 {
cfg.PollInterval = 15 * time.Second
}
if cfg.ActiveConnectionCapacity <= 0 {
cfg.ActiveConnectionCapacity = 20
}
if cfg.ConnectionRateCapacity <= 0 {
cfg.ConnectionRateCapacity = 0.2
}
if cfg.BackendUnhealthyPressure <= 0 {
cfg.BackendUnhealthyPressure = 0.7
}

return &Collector{
cfg:    cfg,
logger: logger,
client: &http.Client{Timeout: 5 * time.Second},
}
}

func (c *Collector) Run(ctx context.Context, out chan<- scorer.SessionSignal) {
if !c.cfg.Enabled {
c.logger.Info("metric-based scaling collector disabled")
return
}

c.logger.Info("metric-based scaling collector started",
"prometheus_url", c.cfg.PrometheusURL,
"poll_interval", c.cfg.PollInterval.String(),
"active_connection_capacity", c.cfg.ActiveConnectionCapacity,
"connection_rate_capacity", c.cfg.ConnectionRateCapacity,
"backend_unhealthy_pressure", c.cfg.BackendUnhealthyPressure,
)

ticker := time.NewTicker(c.cfg.PollInterval)
defer ticker.Stop()

c.collectOnce(ctx, out)

for {
select {
case <-ctx.Done():
c.logger.Info("metric-based scaling collector stopped")
return
case <-ticker.C:
c.collectOnce(ctx, out)
}
}
}

func (c *Collector) collectOnce(ctx context.Context, out chan<- scorer.SessionSignal) {
now := time.Now().UTC()

pgActive, pgActiveOK := c.queryFloat(ctx, "capstone_pgproxy_active_connections")
mysqlActive, mysqlActiveOK := c.queryFloat(ctx, "capstone_mysqlproxy_active_connections")
pgRate, pgRateOK := c.queryFloat(ctx, "rate(capstone_pgproxy_total_connections[1m])")
mysqlRate, mysqlRateOK := c.queryFloat(ctx, "rate(capstone_mysqlproxy_total_connections[1m])")
pgHealthy, pgHealthyOK := c.queryFloat(ctx, "capstone_pgproxy_backend_healthy")
mysqlHealthy, mysqlHealthyOK := c.queryFloat(ctx, "capstone_mysqlproxy_backend_healthy")

if !(pgActiveOK || mysqlActiveOK || pgRateOK || mysqlRateOK || pgHealthyOK || mysqlHealthyOK) {
c.logger.Warn("metric collector skipped cycle; no Prometheus metrics available")
return
}

activeConnections := safe(pgActive) + safe(mysqlActive)
connectionRate := safe(pgRate) + safe(mysqlRate)

connectionPressure := clamp01(activeConnections / c.cfg.ActiveConnectionCapacity)
ratePressure := clamp01(connectionRate / c.cfg.ConnectionRateCapacity)

backendPressure := 0.0
if (pgHealthyOK && pgHealthy < 1) || (mysqlHealthyOK && mysqlHealthy < 1) {
backendPressure = c.cfg.BackendUnhealthyPressure
}

pressure := math.Max(connectionPressure, math.Max(ratePressure, backendPressure))
pressure = clamp01(pressure)

// Set all normalized components to pressure. The scorer's weighted formula
// then produces raw_score == pressure while reusing the same safeguards.
sig := scorer.SessionSignal{
SessionID:          "metric-pressure-prometheus",
ClientIP:           "prometheus",
AttackerConfidence: pressure,
SessionDepth:       pressure,
QueryEntropy:       pressure,
FailedAuthRatio:    pressure,
IsTrapTriggered:    false,
IsSessionClosed:    false,
Timestamp:          now,
}

if pressure >= scorer.ScaleDownThreshold {
c.logger.Info("metric pressure signal",
"pressure", pressure,
"active_connections", activeConnections,
"connection_rate", connectionRate,
"connection_pressure", connectionPressure,
"rate_pressure", ratePressure,
"backend_pressure", backendPressure,
)
} else {
c.logger.Debug("metric pressure signal",
"pressure", pressure,
"active_connections", activeConnections,
"connection_rate", connectionRate,
)
}

select {
case out <- sig:
case <-ctx.Done():
}
}

func (c *Collector) queryFloat(ctx context.Context, query string) (float64, bool) {
endpoint := strings.TrimRight(c.cfg.PrometheusURL, "/") + "/api/v1/query?query=" + url.QueryEscape(query)

req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
if err != nil {
c.logger.Warn("failed to build Prometheus query", "query", query, "error", err)
return 0, false
}

resp, err := c.client.Do(req)
if err != nil {
c.logger.Debug("Prometheus query failed", "query", query, "error", err)
return 0, false
}
defer resp.Body.Close()

if resp.StatusCode < 200 || resp.StatusCode >= 300 {
c.logger.Debug("Prometheus query returned non-2xx", "query", query, "status", resp.StatusCode)
return 0, false
}

var pr promResponse
if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
c.logger.Debug("failed to decode Prometheus response", "query", query, "error", err)
return 0, false
}

if pr.Status != "success" || len(pr.Data.Result) == 0 || len(pr.Data.Result[0].Value) < 2 {
return 0, false
}

var valueString string
if err := json.Unmarshal(pr.Data.Result[0].Value[1], &valueString); err != nil {
c.logger.Debug("failed to parse Prometheus value", "query", query, "error", err)
return 0, false
}

value, err := strconv.ParseFloat(valueString, 64)
if err != nil {
c.logger.Debug("failed to convert Prometheus value", "query", query, "value", valueString, "error", err)
return 0, false
}

return value, true
}

func safe(v float64) float64 {
if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
return 0
}
return v
}

func clamp01(v float64) float64 {
if v < 0 {
return 0
}
if v > 1 {
return 1
}
return v
}

func (c *Collector) String() string {
return fmt.Sprintf("prometheus=%s interval=%s", c.cfg.PrometheusURL, c.cfg.PollInterval)
}
