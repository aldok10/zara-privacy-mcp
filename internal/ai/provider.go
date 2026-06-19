// Package ai provides secure AI/LLM provider access with automatic
// redact-before-send and unredact-after-response.
package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aldok10/zara-privacy-mcp/internal/engine"
)

// Registry manages configured AI providers.
type Registry struct {
	providers map[string]Provider
	client    *http.Client
}

// Provider configuration.
type Provider struct {
	Name    string
	BaseURL string
	APIKey  string
	Models  []string
}

// ChatRequest for LLM chat completion.
type ChatRequest struct {
	Model    string        `json:"model"`
	Messages []ChatMessage `json:"messages"`
	Stream   bool          `json:"stream,omitempty"`
}

// ChatMessage in a conversation.
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatResponse from an LLM provider.
type ChatResponse struct {
	Provider     string `json:"provider"`
	Model        string `json:"model"`
	Content      string `json:"content"`
	Duration     string `json:"duration"`
	TokensUsed   int    `json:"tokens_used,omitempty"`
	Redacted     int    `json:"redacted_fields,omitempty"`
}

// NewRegistry creates an AI provider registry.
func NewRegistry() *Registry {
	return &Registry{
		providers: make(map[string]Provider),
		client:    &http.Client{Timeout: 120 * time.Second},
	}
}

// Add registers an AI provider.
func (r *Registry) Add(p Provider) {
	// Set default base URLs by well-known provider name
	if p.BaseURL == "" {
		switch strings.ToLower(p.Name) {
		case "openai":
			p.BaseURL = "https://api.openai.com"
		case "anthropic":
			p.BaseURL = "https://api.anthropic.com"
		case "gemini", "google":
			p.BaseURL = "https://generativelanguage.googleapis.com"
		case "deepseek":
			p.BaseURL = "https://api.deepseek.com"
		case "openrouter":
			p.BaseURL = "https://openrouter.ai/api"
		case "groq":
			p.BaseURL = "https://api.groq.com/openai"
		}
	}
	r.providers[p.Name] = p
}

// Get returns a provider by name.
func (r *Registry) Get(name string) (Provider, bool) {
	p, ok := r.providers[name]
	return p, ok
}

// List returns all registered provider names.
func (r *Registry) List() []string {
	names := make([]string, 0, len(r.providers))
	for n := range r.providers {
		names = append(names, n)
	}
	return names
}

// Chat sends a chat completion request with automatic redact/unredact.
// The engine is used to: redact the prompt before sending, then unredact the response.
func (r *Registry) Chat(providerName string, req ChatRequest, redactEngine *engine.RedactEngine) (*ChatResponse, error) {
	provider, ok := r.providers[providerName]
	if !ok {
		return nil, fmt.Errorf("unknown provider: %s", providerName)
	}

	start := time.Now()

	// ── Step 1: Redact all messages before sending ──
	totalRedacted := 0
	redactedMessages := make([]ChatMessage, len(req.Messages))
	for i, msg := range req.Messages {
		redactResult := redactEngine.RedactContext(msg.Content)
		redactedMessages[i] = ChatMessage{
			Role:    msg.Role,
			Content: redactResult.Redacted,
		}
		totalRedacted += len(redactResult.Replacements)
	}

	// ── Step 2: Send to provider ──
	chatReq := ChatRequest{
		Model:    req.Model,
		Messages: redactedMessages,
		Stream:   false,
	}

	body, err := json.Marshal(chatReq)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	// Determine API endpoint based on provider
	endpoint := r.chatEndpoint(provider, req.Model)
	httpReq, err := http.NewRequest("POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	r.applyAuth(provider, httpReq)
	httpReq.Header.Set("Content-Type", "application/json")
	if strings.ToLower(providerName) == "anthropic" {
		httpReq.Header.Set("anthropic-version", "2023-06-01")
	}

	httpResp, err := r.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("api call: %w", err)
	}
	defer httpResp.Body.Close()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if httpResp.StatusCode != 200 {
		return nil, fmt.Errorf("%s returned %d: %s", providerName, httpResp.StatusCode, string(respBody))
	}

	// ── Step 3: Parse response ──
	content, err := r.parseResponse(providerName, respBody)
	if err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	// ── Step 4: Unredact the response ──
	content = redactEngine.UnredactResponse(content)

	return &ChatResponse{
		Provider:   providerName,
		Model:      req.Model,
		Content:    content,
		Duration:   time.Since(start).Round(time.Millisecond).String(),
		Redacted:   totalRedacted,
	}, nil
}

// chatEndpoint returns the appropriate chat completion endpoint for a provider.
func (r *Registry) chatEndpoint(p Provider, model string) string {
	name := strings.ToLower(p.Name)
	switch name {
	case "anthropic":
		return fmt.Sprintf("%s/v1/messages", p.BaseURL)
	case "gemini", "google":
		return fmt.Sprintf("%s/v1beta/models/%s:generateContent", p.BaseURL, model)
	default:
		// OpenAI-compatible: /v1/chat/completions
		return fmt.Sprintf("%s/v1/chat/completions", p.BaseURL)
	}
}

// applyAuth sets the appropriate auth header for the provider.
func (r *Registry) applyAuth(p Provider, req *http.Request) {
	name := strings.ToLower(p.Name)
	switch name {
	case "anthropic":
		req.Header.Set("x-api-key", p.APIKey)
	case "gemini", "google":
		// API key goes in query param: ?key=xxx
		q := req.URL.Query()
		q.Set("key", p.APIKey)
		req.URL.RawQuery = q.Encode()
	default:
		// OpenAI-compatible: Authorization: Bearer xxx
		req.Header.Set("Authorization", "Bearer "+p.APIKey)
	}
}

// parseResponse extracts the content text from provider-specific response formats.
func (r *Registry) parseResponse(providerName string, body []byte) (string, error) {
	name := strings.ToLower(providerName)

	switch name {
	case "anthropic":
		// Anthropic format: { "content": [{"type":"text","text":"..."}], "model":"..." }
		var resp struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return "", err
		}
		for _, c := range resp.Content {
			if c.Type == "text" {
				return c.Text, nil
			}
		}
		return "", fmt.Errorf("no text content in response")

	case "gemini", "google":
		// Gemini format: { "candidates": [{"content":{"parts":[{"text":"..."}]}}] }
		var resp struct {
			Candidates []struct {
				Content struct {
					Parts []struct {
						Text string `json:"text"`
					} `json:"parts"`
				} `json:"content"`
			} `json:"candidates"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return "", err
		}
		if len(resp.Candidates) > 0 && len(resp.Candidates[0].Content.Parts) > 0 {
			return resp.Candidates[0].Content.Parts[0].Text, nil
		}
		return "", fmt.Errorf("no candidates in response")

	default:
		// OpenAI-compatible: { "choices": [{"message":{"content":"..."}}] }
		var resp struct {
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return "", err
		}
		if len(resp.Choices) > 0 {
			return resp.Choices[0].Message.Content, nil
		}
		return "", fmt.Errorf("no choices in response")
	}
}
