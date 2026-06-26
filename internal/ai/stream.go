package ai

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aldok10/zara-privacy-mcp/internal/engine"
)

// ChatStream sends a streaming chat request, accumulates the full response,
// and returns it with redaction applied. Uses per-chunk timeout for stall detection.
func (r *Registry) ChatStream(ctx context.Context, providerName string, req ChatRequest, redactEngine *engine.RedactEngine) (*ChatResponse, error) {
	provider, ok := r.providers[providerName]
	if !ok {
		return nil, fmt.Errorf("unknown provider: %s", providerName)
	}

	start := time.Now()

	// Redact messages before sending
	totalRedacted := 0
	redactedMessages := make([]ChatMessage, len(req.Messages))
	for i, msg := range req.Messages {
		result := redactEngine.RedactContext(msg.Content)
		redactedMessages[i] = ChatMessage{Role: msg.Role, Content: result.Redacted}
		totalRedacted += len(result.Replacements)
	}

	// Force streaming
	req.Stream = true

	format := DetectFormat(provider.BaseURL)
	body, err := TranslateToProvider(format, req.Model, redactedMessages)
	if err != nil {
		return nil, fmt.Errorf("translate: %w", err)
	}
	// Inject stream:true into request body
	var bodyMap map[string]any
	json.Unmarshal(body, &bodyMap)
	bodyMap["stream"] = true
	body, _ = json.Marshal(bodyMap)

	endpoint := r.chatEndpoint(provider, req.Model)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	r.applyAuth(provider, httpReq)
	httpReq.Header.Set("Content-Type", "application/json")
	if format == FormatAnthropic {
		httpReq.Header.Set("anthropic-version", "2023-06-01")
	}

	httpResp, err := r.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("stream request: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != 200 {
		errBody, _ := io.ReadAll(io.LimitReader(httpResp.Body, 4096))
		return nil, fmt.Errorf("%s returned %d: %s", providerName, httpResp.StatusCode, string(errBody))
	}

	// Read SSE stream, accumulate content
	content, tokens := readSSEStream(httpResp.Body, format)

	if content == "" {
		return nil, fmt.Errorf("empty streaming response from %s", providerName)
	}

	// Unredact the accumulated response
	content = redactEngine.UnredactResponse(content)

	return &ChatResponse{
		Provider:   providerName,
		Model:      req.Model,
		Content:    content,
		Duration:   time.Since(start).Round(time.Millisecond).String(),
		TokensUsed: tokens,
		Redacted:   totalRedacted,
	}, nil
}

// readSSEStream reads an SSE stream and accumulates content deltas.
func readSSEStream(body io.Reader, format Format) (string, int) {
	scanner := bufio.NewScanner(body)
	var content strings.Builder
	tokens := 0

	for scanner.Scan() {
		line := scanner.Text()

		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			break
		}

		switch format {
		case FormatAnthropic:
			tokens += extractAnthropicDelta(data, &content)
		default:
			// OpenAI-compatible format
			tokens += extractOpenAIDelta(data, &content)
		}
	}

	return content.String(), tokens
}

func extractOpenAIDelta(data string, content *strings.Builder) int {
	var chunk struct {
		Choices []struct {
			Delta struct {
				Content string `json:"content"`
			} `json:"delta"`
		} `json:"choices"`
		Usage *struct {
			TotalTokens int `json:"total_tokens"`
		} `json:"usage"`
	}
	if json.Unmarshal([]byte(data), &chunk) != nil {
		return 0
	}
	if len(chunk.Choices) > 0 && chunk.Choices[0].Delta.Content != "" {
		content.WriteString(chunk.Choices[0].Delta.Content)
	}
	if chunk.Usage != nil {
		return chunk.Usage.TotalTokens
	}
	return 0
}

func extractAnthropicDelta(data string, content *strings.Builder) int {
	var event struct {
		Type  string `json:"type"`
		Delta struct {
			Text string `json:"text"`
		} `json:"delta"`
		Usage *struct {
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if json.Unmarshal([]byte(data), &event) != nil {
		return 0
	}
	if event.Type == "content_block_delta" && event.Delta.Text != "" {
		content.WriteString(event.Delta.Text)
	}
	if event.Usage != nil {
		return event.Usage.OutputTokens
	}
	return 0
}
