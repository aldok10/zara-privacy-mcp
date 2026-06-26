package ai

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aldok10/zara-privacy-mcp/internal/detector"
	"github.com/aldok10/zara-privacy-mcp/internal/engine"
	"github.com/aldok10/zara-privacy-mcp/internal/store"
)

func newTestEngine(t *testing.T) *engine.RedactEngine {
	t.Helper()
	st, err := store.NewMappingStore(t.TempDir()+"/test.db", []byte("testkey1234567890"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return engine.NewRedactEngine(detector.NewSecretDetector(), detector.NewPIIDetector(), st)
}

func TestChatWithFallback_PrimarySuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]string{"content": "hello"}},
			},
			"usage": map[string]int{"total_tokens": 10},
		})
	}))
	defer srv.Close()

	reg := NewRegistry()
	reg.Add(Provider{Name: "primary", BaseURL: srv.URL, APIKey: "k"})
	eng := newTestEngine(t)

	router := NewRouter(reg, eng, RouterConfig{Fallback: []string{"backup"}, MaxRetries: 1})

	resp, err := router.ChatWithFallback("primary", ChatRequest{
		Model:    "test",
		Messages: []ChatMessage{{Role: "user", Content: "hi"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Provider != "primary" {
		t.Errorf("got provider %q, want primary", resp.Provider)
	}
	if resp.Content != "hello" {
		t.Errorf("got content %q, want hello", resp.Content)
	}
}

func TestChatWithFallback_PrimaryFailsFallbackSucceeds(t *testing.T) {
	var calls atomic.Int32

	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(500)
	}))
	defer primary.Close()

	backup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]string{"content": "from backup"}},
			},
			"usage": map[string]int{"total_tokens": 5},
		})
	}))
	defer backup.Close()

	reg := NewRegistry()
	reg.Add(Provider{Name: "primary", BaseURL: primary.URL, APIKey: "k"})
	reg.Add(Provider{Name: "backup", BaseURL: backup.URL, APIKey: "k"})
	eng := newTestEngine(t)

	router := NewRouter(reg, eng, RouterConfig{Fallback: []string{"backup"}, MaxRetries: 1})

	resp, err := router.ChatWithFallback("primary", ChatRequest{
		Model:    "test",
		Messages: []ChatMessage{{Role: "user", Content: "hi"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Provider != "backup" {
		t.Errorf("got provider %q, want backup", resp.Provider)
	}
	if resp.Content != "from backup" {
		t.Errorf("got content %q, want 'from backup'", resp.Content)
	}
}

func TestChatWithFallback_AllFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	reg := NewRegistry()
	reg.Add(Provider{Name: "a", BaseURL: srv.URL, APIKey: "k"})
	reg.Add(Provider{Name: "b", BaseURL: srv.URL, APIKey: "k"})
	eng := newTestEngine(t)

	router := NewRouter(reg, eng, RouterConfig{Fallback: []string{"b"}, MaxRetries: 1})

	_, err := router.ChatWithFallback("a", ChatRequest{
		Model:    "test",
		Messages: []ChatMessage{{Role: "user", Content: "hi"}},
	})
	if err == nil {
		t.Fatal("expected error when all providers fail")
	}
}

func TestChatWithFallback_QuotaExhaustedSkips(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]string{"content": "ok"}},
			},
			"usage": map[string]int{"total_tokens": 5},
		})
	}))
	defer srv.Close()

	reg := NewRegistry()
	reg.Add(Provider{Name: "expensive", BaseURL: srv.URL, APIKey: "k"})
	reg.Add(Provider{Name: "cheap", BaseURL: srv.URL, APIKey: "k"})
	eng := newTestEngine(t)

	router := NewRouter(reg, eng, RouterConfig{Fallback: []string{"cheap"}, MaxRetries: 1})

	// Exhaust quota for "expensive"
	router.Quota().SetLimit("expensive", 1, time.Hour)
	router.Quota().Record("expensive", 1)

	resp, err := router.ChatWithFallback("expensive", ChatRequest{
		Model:    "test",
		Messages: []ChatMessage{{Role: "user", Content: "hi"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Provider != "cheap" {
		t.Errorf("got provider %q, want cheap (expensive should be skipped)", resp.Provider)
	}
}
