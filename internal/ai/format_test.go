package ai

import (
	"encoding/json"
	"testing"
)

func TestDetectFormat(t *testing.T) {
	tests := []struct {
		url  string
		want Format
	}{
		{"https://api.openai.com/v1", FormatOpenAI},
		{"https://api.anthropic.com", FormatAnthropic},
		{"https://generativelanguage.googleapis.com", FormatGemini},
		{"https://api.deepseek.com", FormatOpenAI},
		{"https://openrouter.ai/api", FormatOpenAI},
	}
	for _, tc := range tests {
		if got := DetectFormat(tc.url); got != tc.want {
			t.Errorf("DetectFormat(%q) = %d, want %d", tc.url, got, tc.want)
		}
	}
}

func TestTranslateToProvider_OpenAI(t *testing.T) {
	msgs := []ChatMessage{{Role: "user", Content: "hi"}}
	body, err := TranslateToProvider(FormatOpenAI, "gpt-4o", msgs)
	if err != nil {
		t.Fatal(err)
	}
	var req map[string]interface{}
	json.Unmarshal(body, &req)
	if req["model"] != "gpt-4o" {
		t.Errorf("want model gpt-4o, got %v", req["model"])
	}
}

func TestTranslateToProvider_Anthropic(t *testing.T) {
	msgs := []ChatMessage{
		{Role: "system", Content: "you are helpful"},
		{Role: "user", Content: "hi"},
	}
	body, err := TranslateToProvider(FormatAnthropic, "claude-3", msgs)
	if err != nil {
		t.Fatal(err)
	}
	var req map[string]interface{}
	json.Unmarshal(body, &req)
	if req["system"] != "you are helpful" {
		t.Error("expected system as top-level field")
	}
	messages := req["messages"].([]interface{})
	if len(messages) != 1 {
		t.Errorf("expected 1 message (system extracted), got %d", len(messages))
	}
}

func TestExtractContent_OpenAI(t *testing.T) {
	resp := `{"choices":[{"message":{"content":"hello"}}],"usage":{"total_tokens":10}}`
	content, tokens := ExtractContent(FormatOpenAI, []byte(resp))
	if content != "hello" {
		t.Errorf("want hello, got %q", content)
	}
	if tokens != 10 {
		t.Errorf("want 10 tokens, got %d", tokens)
	}
}

func TestExtractContent_Anthropic(t *testing.T) {
	resp := `{"content":[{"text":"hi"}],"usage":{"input_tokens":5,"output_tokens":3}}`
	content, tokens := ExtractContent(FormatAnthropic, []byte(resp))
	if content != "hi" {
		t.Errorf("want hi, got %q", content)
	}
	if tokens != 8 {
		t.Errorf("want 8 tokens, got %d", tokens)
	}
}
