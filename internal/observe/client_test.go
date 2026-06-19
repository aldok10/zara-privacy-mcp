package observe

import (
	"testing"
	"time"
)

func TestNew_EmptyURL(t *testing.T) {
	c := New(Config{URL: ""})
	if c != nil {
		t.Error("expected nil client for empty URL")
	}
}

func TestNew_ValidURL(t *testing.T) {
	c := New(Config{URL: "http://localhost:5080", Stream: "test"})
	if c == nil {
		t.Fatal("expected non-nil client")
	}
	if c.url != "http://localhost:5080/api/default/test/_json" {
		t.Errorf("unexpected url: %s", c.url)
	}
}

func TestNew_DefaultStream(t *testing.T) {
	c := New(Config{URL: "http://localhost:5080"})
	if c == nil {
		t.Fatal("expected non-nil")
	}
	if c.url != "http://localhost:5080/api/default/zara-mcp/_json" {
		t.Errorf("expected default stream, got %s", c.url)
	}
}

func TestLogTool_NilSafe(t *testing.T) {
	var c *Client
	// Should not panic
	c.LogTool("test", time.Second, "ok", 0)
}
