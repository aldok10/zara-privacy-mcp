package ai

type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ChatRequest struct {
	Model    string        `json:"model"`
	Messages []ChatMessage `json:"messages"`
}

type ChatResponse struct {
	Content        string `json:"content"`
	Model          string `json:"model"`
	Provider       string `json:"provider"`
	RedactedFields int    `json:"redacted_fields"`
	Duration       string `json:"duration"`
}

type Provider interface {
	Chat(req ChatRequest) (*ChatResponse, error)
	Name() string
	Models() []string
}

type Registry interface {
	Chat(providerName string, req ChatRequest) (*ChatResponse, error)
	Get(name string) (Provider, bool)
	List() []string
}
