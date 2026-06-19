package ai

import (
	"testing"
)

func TestPool_RoundRobin(t *testing.T) {
	p := NewPool("test",
		Provider{Name: "test", APIKey: "key1"},
		Provider{Name: "test", APIKey: "key2"},
		Provider{Name: "test", APIKey: "key3"},
	)

	keys := make([]string, 6)
	for i := range keys {
		keys[i] = p.Next().APIKey
	}

	// Should cycle: key1, key2, key3, key1, key2, key3
	if keys[0] != "key1" || keys[1] != "key2" || keys[2] != "key3" {
		t.Errorf("first cycle: %v", keys[:3])
	}
	if keys[3] != "key1" || keys[4] != "key2" || keys[5] != "key3" {
		t.Errorf("second cycle: %v", keys[3:])
	}
}

func TestPool_Empty(t *testing.T) {
	p := NewPool("empty")
	got := p.Next()
	if got.Name != "empty" {
		t.Errorf("want name empty, got %s", got.Name)
	}
}

func TestPool_Len(t *testing.T) {
	p := NewPool("x", Provider{}, Provider{})
	if p.Len() != 2 {
		t.Errorf("want len 2, got %d", p.Len())
	}
}

func TestBuildFallbackChain(t *testing.T) {
	providers := []TieredProvider{
		{Provider: Provider{Name: "free1"}, Tier: TierFree},
		{Provider: Provider{Name: "sub1"}, Tier: TierSubscription},
		{Provider: Provider{Name: "cheap1"}, Tier: TierCheap},
		{Provider: Provider{Name: "free2"}, Tier: TierFree},
	}

	chain := BuildFallbackChain(providers)

	// Order: subscription, cheap, free
	if chain[0] != "sub1" {
		t.Errorf("first should be subscription, got %s", chain[0])
	}
	if chain[1] != "cheap1" {
		t.Errorf("second should be cheap, got %s", chain[1])
	}
	if chain[2] != "free1" || chain[3] != "free2" {
		t.Errorf("last should be free, got %v", chain[2:])
	}
}

func TestTier_String(t *testing.T) {
	tests := []struct {
		tier Tier
		want string
	}{
		{TierFree, "free"},
		{TierCheap, "cheap"},
		{TierSubscription, "subscription"},
		{Tier(99), "unknown"},
	}
	for _, tc := range tests {
		if got := tc.tier.String(); got != tc.want {
			t.Errorf("Tier(%d).String() = %q, want %q", tc.tier, got, tc.want)
		}
	}
}
