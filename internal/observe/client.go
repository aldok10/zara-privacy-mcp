// Package observe provides OpenObserve integration for logging and telemetry.
package observe

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Client sends logs to OpenObserve.
type Client struct {
	url    string // e.g. http://localhost:5080/api/default/zara-mcp/_json
	user   string
	key    string
	stream string
	client *http.Client
	buf    []LogEntry
	mu     sync.Mutex
}

// LogEntry represents a single log event.
type LogEntry struct {
	Timestamp string      `json:"_timestamp"`
	Level     string      `json:"level"`
	Method    string      `json:"method,omitempty"`
	Tool      string      `json:"tool,omitempty"`
	Duration  float64     `json:"duration_ms,omitempty"`
	Status    string      `json:"status,omitempty"`
	Message   string      `json:"message,omitempty"`
	Masked    int         `json:"masked_count,omitempty"`
	Meta      interface{} `json:"meta,omitempty"`
}

// Config for the OpenObserve client.
type Config struct {
	URL    string // OpenObserve base URL (e.g. http://localhost:5080)
	User   string // basic auth user
	Key    string // basic auth password / API key
	Stream string // stream/index name (default: "zara-mcp")
}

// New creates an OpenObserve client. Returns nil if config is incomplete.
func New(cfg Config) *Client {
	if cfg.URL == "" {
		return nil
	}
	if cfg.Stream == "" {
		cfg.Stream = "zara-mcp"
	}

	return &Client{
		url:    fmt.Sprintf("%s/api/default/%s/_json", cfg.URL, cfg.Stream),
		user:   cfg.User,
		key:    cfg.Key,
		stream: cfg.Stream,
		client: &http.Client{Timeout: 5 * time.Second},
	}
}

// Log sends a single log entry immediately.
func (c *Client) Log(entry LogEntry) {
	if c == nil {
		return
	}
	if entry.Timestamp == "" {
		entry.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	go c.send([]LogEntry{entry})
}

// LogTool logs an MCP tool invocation.
func (c *Client) LogTool(tool string, duration time.Duration, status string, maskedCount int) {
	if c == nil {
		return
	}
	c.Log(LogEntry{
		Level:    "info",
		Method:   "call_tool",
		Tool:     tool,
		Duration: float64(duration.Microseconds()) / 1000.0,
		Status:   status,
		Masked:   maskedCount,
	})
}

// LogError logs an error event.
func (c *Client) LogError(tool, message string) {
	if c == nil {
		return
	}
	c.Log(LogEntry{
		Level:   "error",
		Tool:    tool,
		Status:  "error",
		Message: message,
	})
}

func (c *Client) send(entries []LogEntry) {
	body, err := json.Marshal(entries)
	if err != nil {
		return
	}

	req, err := http.NewRequest("POST", c.url, bytes.NewReader(body))
	if err != nil {
		return
	}

	req.Header.Set("Content-Type", "application/json")
	if c.user != "" && c.key != "" {
		req.SetBasicAuth(c.user, c.key)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}
