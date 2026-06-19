package ai

import (
	"encoding/json"
	"strings"
)

// Format represents an AI provider's message format.
type Format int

const (
	FormatOpenAI    Format = iota // OpenAI/compatible (default)
	FormatAnthropic               // Anthropic (system separate, content blocks)
	FormatGemini                  // Google Gemini (parts-based)
)

// DetectFormat returns the format for a provider based on its base URL.
func DetectFormat(baseURL string) Format {
	lower := strings.ToLower(baseURL)
	switch {
	case strings.Contains(lower, "anthropic"):
		return FormatAnthropic
	case strings.Contains(lower, "generativelanguage.googleapis"):
		return FormatGemini
	default:
		return FormatOpenAI
	}
}

// TranslateToProvider converts standard ChatMessages to provider-specific request body.
func TranslateToProvider(format Format, model string, messages []ChatMessage) ([]byte, error) {
	switch format {
	case FormatAnthropic:
		return toAnthropic(model, messages)
	case FormatGemini:
		return toGemini(model, messages)
	default:
		return toOpenAI(model, messages)
	}
}

// ExtractContent extracts the assistant response content from provider-specific response body.
func ExtractContent(format Format, body []byte) (string, int) {
	switch format {
	case FormatAnthropic:
		return fromAnthropic(body)
	case FormatGemini:
		return fromGemini(body)
	default:
		return fromOpenAI(body)
	}
}

// ─── OpenAI format ──────────────────────────────────────────────────────────

func toOpenAI(model string, messages []ChatMessage) ([]byte, error) {
	req := map[string]interface{}{
		"model":    model,
		"messages": messages,
	}
	return json.Marshal(req)
}

func fromOpenAI(body []byte) (string, int) {
	var resp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			TotalTokens int `json:"total_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || len(resp.Choices) == 0 {
		return "", 0
	}
	return resp.Choices[0].Message.Content, resp.Usage.TotalTokens
}

// ─── Anthropic format ───────────────────────────────────────────────────────

func toAnthropic(model string, messages []ChatMessage) ([]byte, error) {
	// Anthropic expects system as top-level field, not in messages
	var system string
	var filtered []ChatMessage
	for _, m := range messages {
		if m.Role == "system" {
			system = m.Content
		} else {
			filtered = append(filtered, m)
		}
	}

	req := map[string]interface{}{
		"model":      model,
		"max_tokens": 8192,
		"messages":   filtered,
	}
	if system != "" {
		req["system"] = system
	}
	return json.Marshal(req)
}

func fromAnthropic(body []byte) (string, int) {
	var resp struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || len(resp.Content) == 0 {
		return "", 0
	}
	return resp.Content[0].Text, resp.Usage.InputTokens + resp.Usage.OutputTokens
}

// ─── Gemini format ──────────────────────────────────────────────────────────

func toGemini(model string, messages []ChatMessage) ([]byte, error) {
	var contents []map[string]interface{}
	for _, m := range messages {
		role := m.Role
		if role == "assistant" {
			role = "model"
		}
		if role == "system" {
			role = "user" // Gemini doesn't have system, prepend as user
		}
		contents = append(contents, map[string]interface{}{
			"role":  role,
			"parts": []map[string]string{{"text": m.Content}},
		})
	}
	req := map[string]interface{}{
		"contents": contents,
	}
	return json.Marshal(req)
}

func fromGemini(body []byte) (string, int) {
	var resp struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
		UsageMetadata struct {
			TotalTokenCount int `json:"totalTokenCount"`
		} `json:"usageMetadata"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || len(resp.Candidates) == 0 {
		return "", 0
	}
	if len(resp.Candidates[0].Content.Parts) == 0 {
		return "", 0
	}
	return resp.Candidates[0].Content.Parts[0].Text, resp.UsageMetadata.TotalTokenCount
}
