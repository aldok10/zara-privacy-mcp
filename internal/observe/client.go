// Package observe provides OpenObserve integration for tool call telemetry.
package observe

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Client sends structured logs to OpenObserve.
type Client struct {
	url    string
	user   string
	key    string
	client *http.Client
}

// Config for the OpenObserve client.
type Config struct {
	URL    string // Base URL (e.g. http://localhost:5080)
	User   string // Basic auth user
	Key    string // Basic auth password / API key
	Stream string // Stream name (default: "zara-mcp")
}

// LogEntry is a single telemetry event.
type LogEntry struct {
	Timestamp string  `json:"_timestamp"`
	Level     string  `json:"level"`
	Tool      string  `json:"tool,omitempty"`
	Duration  float64 `json:"duration_ms,omitempty"`
	Status    string  `json:"status,omitempty"`
	Masked    int     `json:"masked_count,omitempty"`
}

// New creates an OpenObserve client. Returns nil if URL is empty.
func New(cfg Config) *Client {
	if cfg.URL == "" {
		return nil
	}
	stream := cfg.Stream
	if stream == "" {
		stream = "zara-mcp"
	}
	return &Client{
		url:    fmt.Sprintf("%s/api/default/%s/_json", cfg.URL, stream),
		user:   cfg.User,
		key:    cfg.Key,
		client: &http.Client{Timeout: 5 * time.Second},
	}
}

// LogTool sends a tool invocation event. Non-blocking (fire and forget).
func (c *Client) LogTool(tool string, duration time.Duration, status string, masked int) {
	if c == nil {
		return
	}
	go c.send(LogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Level:     "info",
		Tool:      tool,
		Duration:  float64(duration.Milliseconds()),
		Status:    status,
		Masked:    masked,
	})
}

func (c *Client) send(entry LogEntry) {
	body, err := json.Marshal([]LogEntry{entry})
	if err != nil {
		return
	}
	req, err := http.NewRequest(http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if c.user != "" || c.key != "" {
		req.SetBasicAuth(c.user, c.key)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}
