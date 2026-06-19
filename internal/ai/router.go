package ai

import (
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aldok10/zara-privacy-mcp/internal/engine"
)

// RouterConfig defines fallback and routing behavior.
type RouterConfig struct {
	// Fallback provider names in priority order.
	// If primary fails, tries next in list.
	Fallback []string
	// MaxRetries per provider before moving to next.
	MaxRetries int
}

// UsageStats tracks token usage per provider.
type UsageStats struct {
	Provider    string `json:"provider"`
	TotalCalls  int64  `json:"total_calls"`
	TotalTokens int64  `json:"total_tokens"`
	Errors      int64  `json:"errors"`
	LastUsed    string `json:"last_used,omitempty"`
}

// Router wraps Registry with auto-fallback, quota, and compression.
type Router struct {
	registry *Registry
	engine   *engine.RedactEngine
	config   RouterConfig
	quota    *Quota
	pools    map[string]*Pool // multi-account pools per provider
	usage    map[string]*usageEntry
	mu       sync.RWMutex
}

type usageEntry struct {
	calls  atomic.Int64
	tokens atomic.Int64
	errors atomic.Int64
	last   atomic.Value // stores time.Time
}

// NewRouter creates a router with fallback support.
func NewRouter(reg *Registry, eng *engine.RedactEngine, cfg RouterConfig) *Router {
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 1
	}
	return &Router{
		registry: reg,
		engine:   eng,
		config:   cfg,
		quota:    NewQuota(),
		pools:    make(map[string]*Pool),
		usage:    make(map[string]*usageEntry),
	}
}

// Quota returns the quota tracker for external configuration.
func (rt *Router) Quota() *Quota { return rt.quota }

// AddPool registers a multi-account pool for round-robin routing.
func (rt *Router) AddPool(pool *Pool) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.pools[pool.Name] = pool
}

// ChatWithFallback tries the primary provider, then falls back through
// configured alternatives. Applies token compression and quota checks.
// If a provider has a pool, round-robins between accounts.
func (rt *Router) ChatWithFallback(providerName string, req ChatRequest) (*ChatResponse, error) {
	// Compress tool_result messages (RTK-style, saves 20-40% tokens)
	req.Messages = CompressToolResults(req.Messages)

	// Build provider chain: requested first, then fallbacks (skip quota-exhausted)
	chain := []string{providerName}
	for _, fb := range rt.config.Fallback {
		if fb != providerName {
			chain = append(chain, fb)
		}
	}

	var lastErr error
	for _, name := range chain {
		if !rt.quota.Available(name) {
			log.Printf("[AI-ROUTER] %s: quota exhausted, skipping", name)
			continue
		}

		// Check if pool exists — use round-robin account
		rt.mu.RLock()
		pool, hasPool := rt.pools[name]
		rt.mu.RUnlock()

		if hasPool && pool.Len() > 0 {
			// Round-robin through pool accounts
			p := pool.Next()
			rt.registry.Add(p) // ensure latest account is registered
		} else if _, ok := rt.registry.Get(name); !ok {
			continue
		}

		for attempt := 0; attempt < rt.config.MaxRetries; attempt++ {
			resp, err := rt.registry.Chat(name, req, rt.engine)
			if err == nil {
				rt.quota.Record(name, int64(resp.TokensUsed))
				rt.trackSuccess(name, resp.TokensUsed)
				return resp, nil
			}
			lastErr = err
			rt.trackError(name)
			log.Printf("[AI-ROUTER] %s attempt %d failed", name, attempt+1)
		}
	}

	return nil, fmt.Errorf("all providers failed, last error: %v", lastErr)
}

// Stats returns usage statistics for all providers.
func (rt *Router) Stats() []UsageStats {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	var stats []UsageStats
	for name, entry := range rt.usage {
		s := UsageStats{
			Provider:    name,
			TotalCalls:  entry.calls.Load(),
			TotalTokens: entry.tokens.Load(),
			Errors:      entry.errors.Load(),
		}
		if last, ok := entry.last.Load().(time.Time); ok {
			s.LastUsed = last.Format(time.RFC3339)
		}
		stats = append(stats, s)
	}
	return stats
}

func (rt *Router) trackSuccess(name string, tokens int) {
	entry := rt.getOrCreate(name)
	entry.calls.Add(1)
	entry.tokens.Add(int64(tokens))
	entry.last.Store(time.Now())
}

func (rt *Router) trackError(name string) {
	entry := rt.getOrCreate(name)
	entry.errors.Add(1)
}

func (rt *Router) getOrCreate(name string) *usageEntry {
	rt.mu.RLock()
	entry, ok := rt.usage[name]
	rt.mu.RUnlock()
	if ok {
		return entry
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()
	if entry, ok = rt.usage[name]; ok {
		return entry
	}
	entry = &usageEntry{}
	rt.usage[name] = entry
	return entry
}
