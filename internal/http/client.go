// Package http provides secure HTTP API access with automatic masking.
// Acts as a safer alternative to raw curl — auth headers are managed
// by the MCP, and responses are automatically scanned for secrets/PII.
package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aldok10/zara-privacy-mcp/internal/detector"
)

// Registry manages configured API endpoints.
type Registry struct {
	apis     map[string]APIConfig
	client   *http.Client
	secretDet *detector.SecretDetector
	piiDet    *detector.PIIDetector
}

// APIConfig for an external HTTP API.
type APIConfig struct {
	Name     string
	BaseURL  string
	AuthType string // "none", "bearer", "basic", "header"
	AuthEnv  string // env var name for token
	Headers  map[string]string
}

// Request to send via the API proxy.
type Request struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    json.RawMessage   `json:"body,omitempty"`
	Timeout int               `json:"timeout,omitempty"` // seconds
}

// Response from the API proxy.
type Response struct {
	StatusCode int                 `json:"status_code"`
	Headers    map[string]string   `json:"headers,omitempty"`
	Body       string              `json:"body"`
	Duration   string              `json:"duration"`
	Masked     []detector.Finding  `json:"masked,omitempty"`
}

// NewRegistry creates an API registry with the given configurations.
func NewRegistry(secretDet *detector.SecretDetector, piiDet *detector.PIIDetector) *Registry {
	return &Registry{
		apis:      make(map[string]APIConfig),
		client:    &http.Client{Timeout: 30 * time.Second},
		secretDet: secretDet,
		piiDet:    piiDet,
	}
}

// Add registers an API endpoint.
func (r *Registry) Add(cfg APIConfig) {
	r.apis[cfg.Name] = cfg
}

// Get returns a registered API config.
func (r *Registry) Get(name string) (APIConfig, bool) {
	cfg, ok := r.apis[name]
	return cfg, ok
}

// List returns names of all registered APIs.
func (r *Registry) List() []string {
	names := make([]string, 0, len(r.apis))
	for n := range r.apis {
		names = append(names, n)
	}
	return names
}

// Do sends an HTTP request through the proxy with automatic auth and masking.
func (r *Registry) Do(apiName string, req Request) (*Response, error) {
	cfg, ok := r.apis[apiName]
	if !ok {
		return nil, fmt.Errorf("unknown API: %s (configure via ZARA_API_%s_URL)", apiName, strings.ToUpper(apiName))
	}

	start := time.Now()

	// Build URL
	path := strings.TrimLeft(req.Path, "/")
	url := fmt.Sprintf("%s/%s", cfg.BaseURL, path)

	// Build body
	var bodyReader io.Reader
	if len(req.Body) > 0 {
		bodyReader = bytes.NewReader(req.Body)
	}

	// Create request
	httpReq, err := http.NewRequest(strings.ToUpper(req.Method), url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	// Apply auth
	r.applyAuth(cfg, httpReq)

	// Apply configured headers
	for k, v := range cfg.Headers {
		httpReq.Header.Set(k, v)
	}

	// Apply per-request headers
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	// Default content-type for JSON bodies
	if len(req.Body) > 0 && httpReq.Header.Get("Content-Type") == "" {
		httpReq.Header.Set("Content-Type", "application/json")
	}

	// Apply per-request timeout
	timeout := 30
	if req.Timeout > 0 {
		timeout = req.Timeout
	}
	r.client.Timeout = time.Duration(timeout) * time.Second

	// Execute
	httpResp, err := r.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", req.Method, url, err)
	}
	defer httpResp.Body.Close()

	bodyBytes, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	body := string(bodyBytes)

	// Mask sensitive data in response body
	masked := r.maskResponse(&body)

	// Collect response headers
	respHeaders := make(map[string]string)
	for k := range httpResp.Header {
		respHeaders[k] = httpResp.Header.Get(k)
	}

	return &Response{
		StatusCode: httpResp.StatusCode,
		Headers:    respHeaders,
		Body:       body,
		Duration:   time.Since(start).Round(time.Microsecond).String(),
		Masked:     masked,
	}, nil
}

func (r *Registry) applyAuth(cfg APIConfig, req *http.Request) {
	switch cfg.AuthType {
	case "bearer", "token":
		token := os.Getenv(cfg.AuthEnv)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	case "basic":
		creds := os.Getenv(cfg.AuthEnv)
		if creds != "" {
			parts := strings.SplitN(creds, ":", 2)
			if len(parts) == 2 {
				req.SetBasicAuth(parts[0], parts[1])
			}
		}
	case "header":
		val := os.Getenv(cfg.AuthEnv)
		if val != "" {
			// Use the header name from AuthEnv value format: "HEADER_NAME:value"
			parts := strings.SplitN(cfg.AuthEnv, ":", 2)
			if len(parts) == 2 {
				req.Header.Set(parts[0], os.Getenv(parts[1]))
			}
		}
	}
}

func (r *Registry) maskResponse(body *string) []detector.Finding {
	secrets := r.secretDet.Scan(*body)
	pii := r.piiDet.ScanWithContext(*body)

	var all []detector.Finding
	all = append(all, secrets...)
	all = append(all, pii...)

	if len(all) == 0 {
		return nil
	}

	masked := *body
	for _, f := range all {
		masked = strings.Replace(masked, f.Value, detector.MaskSecret(f.Value), 1)
	}
	*body = masked

	return all
}
