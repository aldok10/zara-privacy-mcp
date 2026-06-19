package ai

import (
	"strings"
	"testing"
	"time"
)

func TestQuota_Record(t *testing.T) {
	q := NewQuota()
	q.SetLimit("openai", 1000, time.Hour)

	if !q.Record("openai", 500) {
		t.Fatal("expected within quota")
	}
	if !q.Available("openai") {
		t.Fatal("expected available")
	}

	if !q.Record("openai", 500) {
		t.Fatal("expected second record within quota")
	}

	if q.Record("openai", 1) {
		t.Fatal("expected over quota")
	}
}

func TestQuota_NoLimit(t *testing.T) {
	q := NewQuota()
	if !q.Record("unknown", 999999) {
		t.Fatal("expected unlimited")
	}
	if !q.Available("unknown") {
		t.Fatal("expected available")
	}
}

func TestQuota_Reset(t *testing.T) {
	q := NewQuota()
	q.SetLimit("test", 100, time.Millisecond)

	q.Record("test", 100)
	if q.Available("test") {
		t.Fatal("expected exhausted before reset")
	}

	time.Sleep(2 * time.Millisecond)

	if !q.Available("test") {
		t.Fatal("expected available after reset")
	}
}

func TestQuota_Status(t *testing.T) {
	q := NewQuota()
	q.SetLimit("p1", 1000, time.Hour)
	q.Record("p1", 300)

	status := q.Status()
	s, ok := status["p1"]
	if !ok {
		t.Fatal("expected p1 in status")
	}
	if s.Used != 300 || s.Remaining != 700 {
		t.Errorf("want used=300 remaining=700, got used=%d remaining=%d", s.Used, s.Remaining)
	}
}

func TestCompressToolResults(t *testing.T) {
	longContent := "line1" + strings.Repeat("\n", 200) + "line2" + strings.Repeat("\n", 200) + "line3" + strings.Repeat("x", 200)
	msgs := []ChatMessage{
		{Role: "user", Content: "hello"},
		{Role: "tool", Content: longContent},
	}

	compressed := CompressToolResults(msgs)

	if compressed[0].Content != "hello" {
		t.Error("user message should not be compressed")
	}
	if compressed[1].Content == msgs[1].Content {
		t.Error("tool message should be compressed (blank lines collapsed)")
	}
}
