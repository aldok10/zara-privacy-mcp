// Package http provides secure HTTP API access with automatic masking.
// Acts as a safer alternative to raw curl — auth headers are managed
// by the MCP, and responses are automatically scanned for secrets/PII.
package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aldok10/zara-privacy-mcp/internal/detector"
	"github.com/aldok10/zara-privacy-mcp/internal/masking"
)

// Registry manages configured API endpoints.
type Registry struct {
	apis      map[string]APIConfig
	client    *http.Client
	masker    *masking.Masker
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
	StatusCode int                `json:"status_code"`
	Headers    map[string]string  `json:"headers,omitempty"`
	Body       string             `json:"body"`
	Duration   string             `json:"duration"`
	Masked     []detector.Finding `json:"masked,omitempty"`
}

// NewRegistry creates an API registry with the given configurations.
func NewRegistry(secretDet *detector.SecretDetector, piiDet *detector.PIIDetector) *Registry {
	return &Registry{
		apis:      make(map[string]APIConfig),
		client:    &http.Client{Timeout: 30 * time.Second},
		masker:    masking.New(secretDet, piiDet),
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
	fullURL := fmt.Sprintf("%s/%s", cfg.BaseURL, path)

	// SSRF protection: validate resolved URL
	if err := validateURL(fullURL); err != nil {
		return nil, err
	}

	// Build body
	var bodyReader io.Reader
	if len(req.Body) > 0 {
		bodyReader = bytes.NewReader(req.Body)
	}

	// Apply per-request timeout via context (thread-safe)
	timeout := 30
	if req.Timeout > 0 {
		timeout = req.Timeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	// Create request
	httpReq, err := http.NewRequestWithContext(ctx, strings.ToUpper(req.Method), fullURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("create request failed")
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

	// Execute with retry (max 3 attempts for transient errors)
	var httpResp *http.Response
	maxRetries := 3
	for attempt := range maxRetries {
		httpResp, err = r.client.Do(httpReq)
		if err == nil && httpResp.StatusCode < 500 {
			break
		}
		if httpResp != nil {
			httpResp.Body.Close()
		}
		if attempt == maxRetries-1 {
			if err != nil {
				return nil, fmt.Errorf("request failed after %d attempts", maxRetries)
			}
			break // use last 5xx response
		}
		// Exponential backoff: 100ms, 200ms
		time.Sleep(time.Duration(100*(attempt+1)) * time.Millisecond)

		// Rebuild request for retry (body needs to be re-readable)
		if len(req.Body) > 0 {
			bodyReader = bytes.NewReader(req.Body)
		}
		httpReq, _ = http.NewRequestWithContext(ctx, strings.ToUpper(req.Method), fullURL, bodyReader)
		r.applyAuth(cfg, httpReq)
		for k, v := range cfg.Headers {
			httpReq.Header.Set(k, v)
		}
		for k, v := range req.Headers {
			httpReq.Header.Set(k, v)
		}
		if len(req.Body) > 0 {
			httpReq.Header.Set("Content-Type", "application/json")
		}
	}
	defer httpResp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(httpResp.Body, 50*1024*1024)) // 50MB max
	if err != nil {
		return nil, fmt.Errorf("read response failed")
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
	masked, findings := r.masker.MaskString(*body)
	if len(findings) > 0 {
		*body = masked
	}
	return findings
}

// validateURL blocks requests to internal/private networks (SSRF prevention).
func validateURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL")
	}

	// Only allow http/https
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("blocked: scheme %q not allowed", parsed.Scheme)
	}

	host := parsed.Hostname()

	// Block cloud metadata endpoints
	if host == "169.254.169.254" || host == "100.100.100.200" || host == "metadata.google.internal" {
		return fmt.Errorf("blocked: cloud metadata endpoint")
	}

	// Block private/internal IPs
	ip := net.ParseIP(host)
	if ip != nil {
		privateRanges := []string{
			"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12",
			"192.168.0.0/16", "169.254.0.0/16", "::1/128", "fc00::/7",
		}
		for _, cidr := range privateRanges {
			_, network, _ := net.ParseCIDR(cidr)
			if network.Contains(ip) {
				return fmt.Errorf("blocked: private/internal IP address")
			}
		}
	}

	return nil
}
