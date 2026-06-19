package ai

import "context"

type Adapter interface {
	Send(ctx context.Context, model string, messages []ChatMessage, apiKey string) (string, error)
	SupportsProvider(baseURL string) bool
}
