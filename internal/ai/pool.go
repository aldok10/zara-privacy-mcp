package ai

import (
	"sync/atomic"
)

// Pool manages multiple accounts/keys for a single provider.
// Round-robins between them for load distribution.
type Pool struct {
	Name     string
	accounts []Provider
	index    atomic.Uint64
}

// NewPool creates a provider pool with multiple accounts.
func NewPool(name string, accounts ...Provider) *Pool {
	return &Pool{Name: name, accounts: accounts}
}

// Next returns the next provider in round-robin order.
func (p *Pool) Next() Provider {
	if len(p.accounts) == 0 {
		return Provider{Name: p.Name}
	}
	idx := p.index.Add(1) - 1
	return p.accounts[idx%uint64(len(p.accounts))]
}

// Len returns the number of accounts in the pool.
func (p *Pool) Len() int { return len(p.accounts) }

// FreeProviders returns preset configurations for well-known free AI providers.
// These require no API key or use OAuth-based free tiers.
func FreeProviders() []Provider {
	return []Provider{
		{
			Name:    "kiro",
			BaseURL: "https://kiro.dev/api/v1",
			Models:  []string{"claude-sonnet-4.5", "claude-haiku-4.5", "glm-5", "minimax-m2.5", "deepseek-3.2", "qwen3-coder-next"},
		},
		{
			Name:    "opencode",
			BaseURL: "https://opencode.ai/zen/v1",
			Models:  []string{"auto"},
		},
		{
			Name:    "codex",
			BaseURL: "https://api.openai.com/v1",
			Models:  []string{"gpt-5.5", "gpt-5.4", "gpt-5.3-codex"},
		},
		{
			Name:    "antigravity",
			BaseURL: "https://api.antigravity.ai/v1",
			Models:  []string{"claude-opus-4.7", "claude-sonnet-4.6"},
		},
		{
			Name:    "mimo",
			BaseURL: "https://api.mimo.ai/v1",
			Models:  []string{"mimo-coder"},
		},
		{
			Name:    "vertex",
			BaseURL: "https://us-central1-aiplatform.googleapis.com/v1",
			Models:  []string{"gemini-3.1-pro-preview", "gemini-3-flash-preview"},
		},
		{
			Name:    "glm",
			BaseURL: "https://open.bigmodel.cn/api/paas/v4",
			Models:  []string{"glm-5.1", "glm-5", "glm-4.7"},
		},
		{
			Name:    "minimax",
			BaseURL: "https://api.minimax.chat/v1",
			Models:  []string{"MiniMax-M2.7", "MiniMax-M2.5"},
		},
		{
			Name:    "deepseek",
			BaseURL: "https://api.deepseek.com",
			Models:  []string{"deepseek-chat", "deepseek-reasoner"},
		},
	}
}

// Tier represents a provider priority tier.
type Tier int

const (
	TierFree         Tier = iota // Free providers (Kiro, OpenCode, etc.)
	TierCheap                    // Cheap providers (GLM $0.6/1M, MiniMax $0.2/1M)
	TierSubscription             // Subscription (Claude Pro, Codex Pro)
)

func (t Tier) String() string {
	switch t {
	case TierFree:
		return "free"
	case TierCheap:
		return "cheap"
	case TierSubscription:
		return "subscription"
	default:
		return "unknown"
	}
}

// TieredProvider is a provider with a cost tier for smart routing.
type TieredProvider struct {
	Provider
	Tier Tier
}

// BuildFallbackChain creates an ordered fallback chain from tiered providers.
// Order: Subscription first (maximize value), then Cheap, then Free.
func BuildFallbackChain(providers []TieredProvider) []string {
	var sub, cheap, free []string
	for _, tp := range providers {
		switch tp.Tier {
		case TierSubscription:
			sub = append(sub, tp.Name)
		case TierCheap:
			cheap = append(cheap, tp.Name)
		case TierFree:
			free = append(free, tp.Name)
		}
	}
	chain := make([]string, 0, len(sub)+len(cheap)+len(free))
	chain = append(chain, sub...)
	chain = append(chain, cheap...)
	chain = append(chain, free...)
	return chain
}
