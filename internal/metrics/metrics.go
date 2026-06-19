// Package metrics provides Prometheus-compatible metrics collection for the MCP server.
package metrics

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Collector tracks operation metrics.
// Phase 2 will add Prometheus /metrics endpoint.
type Collector struct {
	mu sync.RWMutex

	requestsTotal   map[string]int64
	requestsActive  int64
	scanTotal       int64
	piiFoundTotal   int64
	secretsFoundTotal int64
	redactTotal     int64
	replacementsTotal int64
	tokensSavedTotal int64
	durations       map[string][]float64
	errorsTotal     int64
}

// NewCollector creates a new metrics collector.
func NewCollector() *Collector {
	return &Collector{
		requestsTotal: make(map[string]int64),
		durations:     make(map[string][]float64),
	}
}

// IncRequest increments the request counter for a method.
func (c *Collector) IncRequest(method string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requestsTotal[method]++
	c.requestsActive++
}

// DecRequest decrements the active request count.
func (c *Collector) DecRequest() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requestsActive--
}

// ObserveDuration records the duration of an operation.
func (c *Collector) ObserveDuration(method string, seconds float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.durations[method] = append(c.durations[method], seconds)
}

// IncScan increments the scan counter.
func (c *Collector) IncScan(piiCount, secretCount int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.scanTotal++
	c.piiFoundTotal += int64(piiCount)
	c.secretsFoundTotal += int64(secretCount)
}

// IncRedact increments the redact counter.
func (c *Collector) IncRedact(replacements, tokensSaved int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.redactTotal++
	c.replacementsTotal += int64(replacements)
	c.tokensSavedTotal += int64(tokensSaved)
}

// IncError increments the error counter.
func (c *Collector) IncError() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.errorsTotal++
}

// Snapshot returns a point-in-time snapshot of all metrics.
func (c *Collector) Snapshot() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	snap := map[string]interface{}{
		"requests_total":    sumMap(c.requestsTotal),
		"requests_by_method": copyMap(c.requestsTotal),
		"requests_active":   c.requestsActive,
		"scans_total":       c.scanTotal,
		"pii_found_total":   c.piiFoundTotal,
		"secrets_found_total": c.secretsFoundTotal,
		"redacts_total":     c.redactTotal,
		"replacements_total": c.replacementsTotal,
		"tokens_saved_total": c.tokensSavedTotal,
		"errors_total":      c.errorsTotal,
		"uptime_seconds":    time.Since(c.startTime()).Seconds(),
	}

	return snap
}

// MetricsHandler returns an HTTP handler that serves metrics as Prometheus text format.
func (c *Collector) MetricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		snap := c.Snapshot()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")

		for k, v := range snap {
			switch val := v.(type) {
			case int64:
				fmt.Fprintf(w, "# HELP zara_%s Metric\n# TYPE zara_%s counter\nzara_%s %d\n", k, k, k, val)
			case float64:
				fmt.Fprintf(w, "# HELP zara_%s Metric\n# TYPE zara_%s gauge\nzara_%s %f\n", k, k, k, val)
			}
		}
	})
}

var collectorStartTime = time.Now()

func (c *Collector) startTime() time.Time {
	return collectorStartTime
}

func sumMap(m map[string]int64) int64 {
	var total int64
	for _, v := range m {
		total += v
	}
	return total
}

func copyMap(m map[string]int64) map[string]int64 {
	result := make(map[string]int64, len(m))
	for k, v := range m {
		result[k] = v
	}
	return result
}
