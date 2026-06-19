// Package mcp implements the Model Context Protocol server.
// It exposes tools for scanning, redacting, unredacting, compressing,
// classifying, and filtering context between OpenCode and LLM providers.
package mcp

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aldok10/zara-privacy-mcp/internal/classify"
	"github.com/aldok10/zara-privacy-mcp/internal/compress"
	"github.com/aldok10/zara-privacy-mcp/internal/detector"
	"github.com/aldok10/zara-privacy-mcp/internal/engine"
	"github.com/aldok10/zara-privacy-mcp/internal/metrics"
	"github.com/aldok10/zara-privacy-mcp/internal/store"
)

// Server is the MCP server that exposes privacy tools.
type Server struct {
	config     *Config
	engine     *engine.RedactEngine
	compressor *compress.Compressor
	classifier *classify.Classifier
	store      *store.MappingStore
	metrics    *metrics.Collector
	mu         sync.RWMutex

	// In-flight redaction tracking
	activeRedactions map[string]*RedactionSession
}

// Config for the MCP server.
type Config struct {
	Port           string
	Host           string
	ServerName     string
	ServerVersion  string
	DefaultLocales []string
	MaxTokens      int
}

// RedactionSession tracks a conversation's redaction state.
type RedactionSession struct {
	ID        string
	CreatedAt time.Time
	Contexts  []string
}

// JSON-RPC request/response types.
type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *rpcError   `json:"error,omitempty"`
}

type rpcError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// NewServer creates and initializes the MCP server.
func NewServer(cfg *Config, secretDet *detector.SecretDetector, piiDet *detector.PIIDetector, ms *store.MappingStore) *Server {
	return &Server{
		config:           cfg,
		engine:           engine.NewRedactEngine(secretDet, piiDet, ms),
		compressor:       compress.NewCompressor(cfg.MaxTokens),
		classifier:       classify.NewClassifier(),
		store:            ms,
		metrics:          metrics.NewCollector(),
		activeRedactions: make(map[string]*RedactionSession),
	}
}

// Start begins listening for MCP requests.
func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", s.handleMCP)
	mux.HandleFunc("/health", s.handleHealth)

	addr := fmt.Sprintf("%s:%s", s.config.Host, s.config.Port)
	log.Printf("[Zara Privacy MCP] Starting server on %s", addr)
	return http.ListenAndServe(addr, mux)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "ok",
		"server":    s.config.ServerName,
		"version":   s.config.ServerVersion,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"mappings":  s.store.Stats(),
	})
}

func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req rpcRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, nil, -32700, "Parse error", err.Error())
		return
	}

	start := time.Now()
	s.metrics.IncRequest(req.Method)

	var result interface{}
	var rpcErr *rpcError

	switch req.Method {
	case "initialize":
		result = s.handleInitialize(req)
	case "list_tools":
		result = s.handleListTools()
	case "call_tool":
		result, rpcErr = s.handleCallTool(req)
	case "shutdown":
		result = map[string]string{"status": "shutting down"}
	default:
		rpcErr = &rpcError{Code: -32601, Message: "Method not found"}
	}

	duration := time.Since(start).Seconds()
	s.metrics.ObserveDuration(req.Method, duration)

	s.writeResponse(w, req.ID, result, rpcErr)
}

func (s *Server) handleInitialize(req rpcRequest) interface{} {
	return map[string]interface{}{
		"server_name":    s.config.ServerName,
		"server_version": s.config.ServerVersion,
		"protocol_version": "2025-03-26",
		"capabilities": map[string]interface{}{
			"tools": map[string]interface{}{
				"list_changed": true,
			},
		},
	}
}

func (s *Server) handleListTools() interface{} {
	return map[string]interface{}{
		"tools": []map[string]interface{}{
			{
				"name":        "scan_context",
				"description": "Scan conversation context for secrets and PII. Returns risk score, findings, and recommendation without modifying the text.",
				"inputSchema": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"text": map[string]interface{}{
							"type":        "string",
							"description": "The context text to scan",
						},
						"locales": map[string]interface{}{
							"type":        "array",
							"items":       map[string]string{"type": "string"},
							"description": "Locale filters (id, sg, global). Empty = all locales.",
							"default":     []string{"id", "sg", "global"},
						},
					},
					"required": []string{"text"},
				},
			},
			{
				"name":        "redact_context",
				"description": "Replace detected secrets and PII with reversible placeholders. Returns redacted text safe to send to LLM providers.",
				"inputSchema": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"text": map[string]interface{}{
							"type":        "string",
							"description": "The context text to redact",
						},
						"locales": map[string]interface{}{
							"type":        "array",
							"items":       map[string]string{"type": "string"},
							"description": "Locale filters for PII detection",
							"default":     []string{"id", "sg", "global"},
						},
					},
					"required": []string{"text"},
				},
			},
			{
				"name":        "unredact_response",
				"description": "Restore original values in an LLM response by replacing placeholders with original data.",
				"inputSchema": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"text": map[string]interface{}{
							"type":        "string",
							"description": "The LLM response text containing placeholders to restore",
						},
					},
					"required": []string{"text"},
				},
			},
			{
				"name":        "compress_context",
				"description": "Compress context to reduce token usage. Deduplicates lines, removes comments, and optionally extracts relevant sections.",
				"inputSchema": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"text": map[string]interface{}{
							"type":        "string",
							"description": "The context text to compress",
						},
						"keywords": map[string]interface{}{
							"type":        "array",
							"items":       map[string]string{"type": "string"},
							"description": "Keywords for relevance extraction (optional)",
						},
					},
					"required": []string{"text"},
				},
			},
			{
				"name":        "memory_filter",
				"description": "Validate memory content before persistence. Blocks sensitive data from being stored in conversation memory.",
				"inputSchema": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"text": map[string]interface{}{
							"type":        "string",
							"description": "Memory content to validate",
						},
					},
					"required": []string{"text"},
				},
			},
			{
				"name":        "classify_data",
				"description": "Classify data by sensitivity level (PUBLIC, INTERNAL, CONFIDENTIAL, SECRET). Uses scan results and content analysis.",
				"inputSchema": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"text": map[string]interface{}{
							"type":        "string",
							"description": "The data to classify",
						},
					},
					"required": []string{"text"},
				},
			},
			{
				"name":        "store_stats",
				"description": "Get statistics about the placeholder mapping store.",
				"inputSchema": map[string]interface{}{
					"type":       "object",
					"properties": map[string]interface{}{},
				},
			},
		},
	}
}

func (s *Server) handleCallTool(req rpcRequest) (interface{}, *rpcError) {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, &rpcError{Code: -32602, Message: "Invalid params"}
	}

	switch params.Name {
	case "scan_context":
		return s.callScan(params.Arguments)
	case "redact_context":
		return s.callRedact(params.Arguments)
	case "unredact_response":
		return s.callUnredact(params.Arguments)
	case "compress_context":
		return s.callCompress(params.Arguments)
	case "memory_filter":
		return s.callMemoryFilter(params.Arguments)
	case "classify_data":
		return s.callClassify(params.Arguments)
	case "store_stats":
		return s.callStoreStats()
	default:
		return nil, &rpcError{Code: -32601, Message: "Tool not found: " + params.Name}
	}
}

// Tool call handlers

func (s *Server) callScan(args json.RawMessage) (interface{}, *rpcError) {
	var p struct {
		Text    string   `json:"text"`
		Locales []string `json:"locales"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return nil, &rpcError{Code: -32602, Message: "Invalid arguments"}
	}
	if len(p.Locales) == 0 {
		p.Locales = s.config.DefaultLocales
	}

	result := s.engine.ScanContext(p.Text, p.Locales...)
	s.metrics.IncScan(len(result.PIIFound), len(result.SecretsFound))

	return map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "json",
				"json": result,
			},
		},
	}, nil
}

func (s *Server) callRedact(args json.RawMessage) (interface{}, *rpcError) {
	var p struct {
		Text    string   `json:"text"`
		Locales []string `json:"locales"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return nil, &rpcError{Code: -32602, Message: "Invalid arguments"}
	}
	if len(p.Locales) == 0 {
		p.Locales = s.config.DefaultLocales
	}

	result := s.engine.RedactContext(p.Text, p.Locales...)
	s.metrics.IncRedact(len(result.Replacements), result.TokensSaved)

	return map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "json",
				"json": result,
			},
		},
	}, nil
}

func (s *Server) callUnredact(args json.RawMessage) (interface{}, *rpcError) {
	var p struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return nil, &rpcError{Code: -32602, Message: "Invalid arguments"}
	}

	restored := s.engine.UnredactResponse(p.Text)

	return map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "text",
				"text": restored,
			},
		},
	}, nil
}

func (s *Server) callCompress(args json.RawMessage) (interface{}, *rpcError) {
	var p struct {
		Text     string   `json:"text"`
		Keywords []string `json:"keywords"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return nil, &rpcError{Code: -32602, Message: "Invalid arguments"}
	}

	beforeTokens := estimateTokens(p.Text)
	compressed := s.compressor.Compress(p.Text, p.Keywords)
	afterTokens := estimateTokens(compressed)

	result := map[string]interface{}{
		"compressed":   compressed,
		"tokens_saved": beforeTokens - afterTokens,
	}

	return map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "json",
				"json": result,
			},
		},
	}, nil
}

func (s *Server) callMemoryFilter(args json.RawMessage) (interface{}, *rpcError) {
	var p struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return nil, &rpcError{Code: -32602, Message: "Invalid arguments"}
	}

	scanResult := s.engine.ScanContext(p.Text)

	var blocked []string
	allowed := true
	reason := ""

	if scanResult.RiskScore >= detector.RiskHigh {
		allowed = false
		reason = "Contains high-risk sensitive data"
		for _, f := range scanResult.SecretsFound {
			if f.Risk >= detector.RiskHigh {
				blocked = append(blocked, f.Type)
			}
		}
	}

	result := &detector.MemoryFilterResult{
		Allowed: allowed,
		Reason:  reason,
		Blocked: blocked,
	}

	return map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "json",
				"json": result,
			},
		},
	}, nil
}

func (s *Server) callClassify(args json.RawMessage) (interface{}, *rpcError) {
	var p struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return nil, &rpcError{Code: -32602, Message: "Invalid arguments"}
	}

	scanResult := s.engine.ScanContext(p.Text)
	classification := s.classifier.Classify(p.Text, scanResult)

	return map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "json",
				"json": classification,
			},
		},
	}, nil
}

func (s *Server) callStoreStats() (interface{}, *rpcError) {
	stats := s.store.Stats()

	return map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "json",
				"json": stats,
			},
		},
	}, nil
}

// writeResponse sends a JSON-RPC response.
func (s *Server) writeResponse(w http.ResponseWriter, id *json.RawMessage, result interface{}, rpcErr *rpcError) {
	w.Header().Set("Content-Type", "application/json")

	resp := rpcResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
		Error:   rpcErr,
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("Error writing response: %v", err)
	}
}

func (s *Server) writeError(w http.ResponseWriter, id *json.RawMessage, code int, message string, data interface{}) {
	s.writeResponse(w, id, nil, &rpcError{
		Code:    code,
		Message: message,
		Data:    data,
	})
}

// estimateTokens roughly estimates token count.
func estimateTokens(s string) int {
	if s == "" {
		return 0
	}
	return len(strings.Fields(s)) + (len(s) / 4)
}

// Stop gracefully shuts down the server.
func (s *Server) Stop() {
	log.Println("[Zara Privacy MCP] Shutting down...")
	if s.store != nil {
		s.store.Close()
	}
}
