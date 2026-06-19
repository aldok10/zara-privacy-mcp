package gateway

import "encoding/json"

type Request struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    json.RawMessage   `json:"body,omitempty"`
	Timeout int               `json:"timeout,omitempty"`
}

type Response struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       string            `json:"body"`
	Duration   string            `json:"duration"`
	Masked     []MaskedItem      `json:"masked,omitempty"`
}

type MaskedItem struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	Risk  int    `json:"risk"`
}

type HTTPProxy interface {
	Do(apiName string, req Request) (*Response, error)
	List() []string
}
