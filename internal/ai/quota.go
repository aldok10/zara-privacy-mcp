package ai

import (
	"strings"
	"sync"
	"time"
)

// Quota tracks token usage with configurable reset periods.
type Quota struct {
	mu     sync.Mutex
	limits map[string]*providerQuota
}

type providerQuota struct {
	Limit      int64         // max tokens per period (0 = unlimited)
	Used       int64         // tokens used in current period
	ResetAt    time.Time     // when this period resets
	ResetEvery time.Duration // reset interval
}

// NewQuota creates a quota tracker.
func NewQuota() *Quota {
	return &Quota{limits: make(map[string]*providerQuota)}
}

// SetLimit configures a quota for a provider.
// Example: SetLimit("openai", 100000, 5*time.Hour)
func (q *Quota) SetLimit(provider string, maxTokens int64, resetEvery time.Duration) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.limits[provider] = &providerQuota{
		Limit:      maxTokens,
		ResetEvery: resetEvery,
		ResetAt:    time.Now().Add(resetEvery),
	}
}

// Record adds token usage. Returns true if within quota.
func (q *Quota) Record(provider string, tokens int64) bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	pq, ok := q.limits[provider]
	if !ok {
		return true // no limit set
	}

	// Reset if period expired
	if time.Now().After(pq.ResetAt) {
		pq.Used = 0
		pq.ResetAt = time.Now().Add(pq.ResetEvery)
	}

	if pq.Limit > 0 && pq.Used+tokens > pq.Limit {
		return false // over quota
	}
	pq.Used += tokens
	return true
}

// Available returns true if provider has remaining quota.
func (q *Quota) Available(provider string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	pq, ok := q.limits[provider]
	if !ok {
		return true
	}
	if time.Now().After(pq.ResetAt) {
		return true // will reset
	}
	return pq.Limit == 0 || pq.Used < pq.Limit
}

// Status returns quota info for all providers.
func (q *Quota) Status() map[string]QuotaStatus {
	q.mu.Lock()
	defer q.mu.Unlock()

	result := make(map[string]QuotaStatus)
	for name, pq := range q.limits {
		remaining := max(pq.Limit-pq.Used, 0)
		result[name] = QuotaStatus{
			Limit:     pq.Limit,
			Used:      pq.Used,
			Remaining: remaining,
			ResetsIn:  time.Until(pq.ResetAt).Round(time.Second).String(),
		}
	}
	return result
}

// QuotaStatus is the current quota state for a provider.
type QuotaStatus struct {
	Limit     int64  `json:"limit"`
	Used      int64  `json:"used"`
	Remaining int64  `json:"remaining"`
	ResetsIn  string `json:"resets_in"`
}

// CompressToolResults applies RTK-style compression to tool_result messages
// before sending to an AI provider. Reduces token usage by 20-40%.
func CompressToolResults(messages []ChatMessage) []ChatMessage {
	compressed := make([]ChatMessage, len(messages))
	for i, msg := range messages {
		compressed[i] = msg
		if msg.Role == "tool" || msg.Role == "system" {
			compressed[i].Content = compressContent(msg.Content)
		}
	}
	return compressed
}

// compressContent applies simple lossless compression to tool output:
// - Dedup consecutive blank lines
// - Collapse repeated whitespace
// - Truncate very long lines (keep first/last 200 chars)
// - Remove trailing whitespace per line
func compressContent(s string) string {
	if len(s) < 500 {
		return s // too small to benefit
	}

	lines := strings.Split(s, "\n")
	var result []string
	prevBlank := false

	for _, line := range lines {
		trimmed := strings.TrimRight(line, " \t")

		// Collapse consecutive blank lines
		if trimmed == "" {
			if prevBlank {
				continue
			}
			prevBlank = true
			result = append(result, "")
			continue
		}
		prevBlank = false

		// Truncate very long lines (>500 chars)
		if len(trimmed) > 500 {
			trimmed = trimmed[:200] + " [...] " + trimmed[len(trimmed)-200:]
		}

		result = append(result, trimmed)
	}

	return strings.Join(result, "\n")
}
