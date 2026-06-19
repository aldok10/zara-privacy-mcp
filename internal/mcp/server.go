// Package mcp implements the Model Context Protocol server.
// It exposes tools for scanning, redacting, unredacting, compressing,
// classifying, and filtering context between OpenCode and LLM providers.
package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aldok10/zara-privacy-mcp/config"
	"github.com/aldok10/zara-privacy-mcp/internal/ai"
	"github.com/aldok10/zara-privacy-mcp/internal/classify"
	"github.com/aldok10/zara-privacy-mcp/internal/compress"
	"github.com/aldok10/zara-privacy-mcp/internal/db"
	"github.com/aldok10/zara-privacy-mcp/internal/detector"
	"github.com/aldok10/zara-privacy-mcp/internal/engine"
	httpproxy "github.com/aldok10/zara-privacy-mcp/internal/http"
	"github.com/aldok10/zara-privacy-mcp/internal/metrics"
	"github.com/aldok10/zara-privacy-mcp/internal/observe"
	"github.com/aldok10/zara-privacy-mcp/internal/store"
)

// Server is the MCP server exposing privacy + gateway tools.
type Server struct {
	cfg           *Config
	appConfig     *config.Config
	engine        *engine.RedactEngine
	compressor    *compress.Compressor
	classifier    *classify.Classifier
	store         *store.MappingStore
	metrics       *metrics.Collector
	observe       *observe.Client
	dbRegistry    *db.Registry
	mongoRegistry *db.MongoRegistry
	redisRegistry *db.RedisRegistry
	apiRegistry   *httpproxy.Registry
	aiRegistry    *ai.Registry
	mu            sync.RWMutex

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
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id"`
	Method  string           `json:"method"`
	Params  json.RawMessage  `json:"params,omitempty"`
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
func NewServer(cfg *Config, appCfg *config.Config, secretDet *detector.SecretDetector, piiDet *detector.PIIDetector, ms *store.MappingStore) *Server {
	s := &Server{
		cfg:              cfg,
		appConfig:        appCfg,
		engine:           engine.NewRedactEngine(secretDet, piiDet, ms),
		compressor:       compress.NewCompressor(cfg.MaxTokens),
		classifier:       classify.NewClassifier(),
		store:            ms,
		metrics:          metrics.NewCollector(),
		observe: observe.New(observe.Config{
			URL:    appCfg.ObserveURL,
			User:   appCfg.ObserveUser,
			Key:    appCfg.ObserveKey,
			Stream: appCfg.ObserveStream,
		}),
		dbRegistry:       db.NewRegistry(),
		mongoRegistry:    db.NewMongoRegistry(),
		redisRegistry:    db.NewRedisRegistry(),
		apiRegistry:      httpproxy.NewRegistry(secretDet, piiDet),
		aiRegistry:       ai.NewRegistry(),
		activeRedactions: make(map[string]*RedactionSession),
	}

	// Register configured SQL databases
	for _, dbc := range appCfg.Databases {
		err := s.dbRegistry.Add(db.Config{
			Name:            dbc.Name,
			Driver:          dbc.Driver,
			DSN:             dbc.DSN,
			MaxConns:        dbc.MaxConns,
			MaxIdleConns:    dbc.MaxIdleConns,
			ConnMaxLifetime: time.Duration(dbc.ConnMaxLifetime) * time.Second,
			ConnMaxIdleTime: time.Duration(dbc.ConnMaxIdleTime) * time.Second,
		}, secretDet, piiDet)
		if err != nil {
			log.Printf("[WARN] DB %s: %v", dbc.Name, err)
		} else {
			log.Printf("[INFO] DB connected: %s (%s)", dbc.Name, dbc.Driver)
		}
	}

	// Register configured MongoDB instances
	for _, mc := range appCfg.MongoDBs {
		err := s.mongoRegistry.Add(db.MongoConfig{
			Name:     mc.Name,
			URI:      mc.URI,
			Database: mc.Database,
		}, secretDet, piiDet)
		if err != nil {
			log.Printf("[WARN] MongoDB %s: %v", mc.Name, err)
		} else {
			log.Printf("[INFO] MongoDB connected: %s/%s", mc.Name, mc.Database)
		}
	}

	// Register configured Redis instances
	for _, rc := range appCfg.RedisDBs {
		err := s.redisRegistry.Add(db.RedisConfig{
			Name:            rc.Name,
			Addr:            rc.Addr,
			Username:        rc.Username,
			Password:        rc.Password,
			DB:              rc.DB,
			PoolSize:        rc.PoolSize,
			MinIdleConns:    rc.MinIdleConns,
			ConnMaxIdleTime: time.Duration(rc.ConnMaxIdleTime) * time.Second,
		}, secretDet, piiDet)
		if err != nil {
			log.Printf("[WARN] Redis %s: %v", rc.Name, err)
		} else {
			log.Printf("[INFO] Redis connected: %s → %s", rc.Name, rc.Addr)
		}
	}

	// Register configured HTTP APIs
	for _, apic := range appCfg.APIs {
		s.apiRegistry.Add(httpproxy.APIConfig{
			Name:     apic.Name,
			BaseURL:  apic.BaseURL,
			AuthType: apic.AuthType,
			AuthEnv:  apic.AuthEnv,
			Headers:  apic.Headers,
		})
		log.Printf("[INFO] API registered: %s → %s", apic.Name, apic.BaseURL)
	}

	// Register configured AI providers
	for _, aic := range appCfg.AIProviders {
		s.aiRegistry.Add(ai.Provider{
			Name:    aic.Name,
			BaseURL: aic.BaseURL,
			APIKey:  aic.APIKey,
			Models:  aic.Models,
		})
		log.Printf("[INFO] AI provider: %s (%d models)", aic.Name, len(aic.Models))
	}

	return s
}

// Start begins listening for MCP requests.
func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", s.handleMCP)
	mux.HandleFunc("/health", s.handleHealth)

	addr := fmt.Sprintf("%s:%s", s.cfg.Host, s.cfg.Port)
	log.Printf("[Zara Privacy MCP] Starting server on %s", addr)
	return http.ListenAndServe(addr, mux)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "ok",
		"server":    s.cfg.ServerName,
		"version":   s.cfg.ServerVersion,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"mappings":  s.store.Stats(),
	})
}

// ---------------------------------------------------------------------------
// Transport-agnostic JSON-RPC handler
// ---------------------------------------------------------------------------

// ServeMessage processes a single JSON-RPC request and returns response bytes.
// Used by both HTTP and stdio transports.
func (s *Server) ServeMessage(raw []byte) []byte {
	// Strip whitespace
	raw = []byte(strings.TrimSpace(string(raw)))
	if len(raw) == 0 {
		return nil
	}

	var req rpcRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return s.marshalResponse(nil, nil, &rpcError{
			Code: -32700, Message: "Parse error", Data: err.Error(),
		})
	}

	start := time.Now()
	s.metrics.IncRequest(req.Method)

	result, rpcErr := s.handleMethod(req)

	duration := time.Since(start)
	s.metrics.ObserveDuration(req.Method, duration.Seconds())

	// OpenObserve telemetry
	if req.Method == "call_tool" {
		status := "ok"
		if rpcErr != nil {
			status = "error"
		}
		s.observe.LogTool(req.Method, duration, status, 0)
	}

	return s.marshalResponse(req.ID, result, rpcErr)
}

// handleMethod routes a parsed JSON-RPC request to the right handler.
func (s *Server) handleMethod(req rpcRequest) (interface{}, *rpcError) {
	switch req.Method {
	case "initialize":
		return s.handleInitialize(req), nil
	case "list_tools":
		return s.handleListTools(), nil
	case "call_tool":
		return s.handleCallTool(req)
	case "shutdown":
		return map[string]string{"status": "shutting down"}, nil
	default:
		return nil, &rpcError{Code: -32601, Message: "Method not found"}
	}
}

// ---------------------------------------------------------------------------
// HTTP Transport
// ---------------------------------------------------------------------------

func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.writeError(w, nil, -32700, "Parse error", err.Error())
		return
	}

	resp := s.ServeMessage(body)
	if resp == nil {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(resp)
}

func (s *Server) handleInitialize(req rpcRequest) interface{} {
	return map[string]interface{}{
		"protocolVersion": "2025-03-26",
		"serverInfo": map[string]interface{}{
			"name":    s.cfg.ServerName,
			"version": s.cfg.ServerVersion,
		},
		"capabilities": map[string]interface{}{
			"tools": map[string]interface{}{
				"listChanged": true,
			},
		},
	}
}

func (s *Server) handleListTools() interface{} {
	return map[string]interface{}{
		"tools": []map[string]interface{}{
			// ── Privacy & Context Tools ──
			{
				"name":        "scan_context",
				"description": "Scan conversation context for secrets and PII. Returns risk score, findings, and recommendation without modifying the text.",
				"inputSchema": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"text":    map[string]interface{}{"type": "string", "description": "The context text to scan"},
						"locales": map[string]interface{}{"type": "array", "items": map[string]string{"type": "string"}, "description": "Locale filters (id, sg, global)", "default": []string{"id", "sg", "global"}},
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
						"text":    map[string]interface{}{"type": "string", "description": "The context text to redact"},
						"locales": map[string]interface{}{"type": "array", "items": map[string]string{"type": "string"}, "description": "Locale filters for PII detection", "default": []string{"id", "sg", "global"}},
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
						"text": map[string]interface{}{"type": "string", "description": "The LLM response text containing placeholders"},
					},
					"required": []string{"text"},
				},
			},
			{
				"name":        "compress_context",
				"description": "Compress context to reduce token usage. Deduplicates lines, removes comments, optionally extracts relevant sections.",
				"inputSchema": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"text":     map[string]interface{}{"type": "string", "description": "The context text to compress"},
						"keywords": map[string]interface{}{"type": "array", "items": map[string]string{"type": "string"}, "description": "Keywords for relevance extraction (optional)"},
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
						"text": map[string]interface{}{"type": "string", "description": "Memory content to validate"},
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
						"text": map[string]interface{}{"type": "string", "description": "The data to classify"},
					},
					"required": []string{"text"},
				},
			},
			{
				"name":        "store_stats",
				"description": "Get statistics about the placeholder mapping store.",
				"inputSchema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
			},

			// ── Database Tools ──
			{
				"name":        "db_query",
				"description": "Execute a SQL query on a configured database. Results are automatically scanned and sensitive data is masked. Supports PostgreSQL, MySQL, MariaDB, SQL Server, SQLite, Oracle, and ClickHouse.",
				"inputSchema": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"database": map[string]interface{}{"type": "string", "description": "Database name (configured via ZARA_DB_<NAME>_DSN)"},
						"query":    map[string]interface{}{"type": "string", "description": "SQL query to execute"},
						"params":   map[string]interface{}{"type": "array", "description": "Query parameters (optional)", "items": map[string]interface{}{}},
					},
					"required": []string{"database", "query"},
				},
			},
			{
				"name":        "db_list_tables",
				"description": "List all tables in a configured database.",
				"inputSchema": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"database": map[string]interface{}{"type": "string", "description": "Database name"},
					},
					"required": []string{"database"},
				},
			},
			{
				"name":        "db_describe",
				"description": "Describe a table's schema (columns, types, nullability).",
				"inputSchema": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"database": map[string]interface{}{"type": "string", "description": "Database name"},
						"table":    map[string]interface{}{"type": "string", "description": "Table name"},
					},
					"required": []string{"database", "table"},
				},
			},

			// ── HTTP API Tools ──
			{
				"name":        "mongo_find",
				"description": "Query documents from a configured MongoDB collection. Results are automatically scanned and sensitive data is masked.",
				"inputSchema": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"database":   map[string]interface{}{"type": "string", "description": "MongoDB name (configured via ZARA_MONGO_<NAME>_URI)"},
						"collection": map[string]interface{}{"type": "string", "description": "Collection name"},
						"filter":     map[string]interface{}{"type": "object", "description": "MongoDB filter (JSON object, optional)", "default": map[string]interface{}{}},
						"limit":      map[string]interface{}{"type": "integer", "description": "Max documents to return (default 20)", "default": 20},
					},
					"required": []string{"database", "collection"},
				},
			},
			{
				"name":        "mongo_list_collections",
				"description": "List all collections in a configured MongoDB database.",
				"inputSchema": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"database": map[string]interface{}{"type": "string", "description": "MongoDB name"},
					},
					"required": []string{"database"},
				},
			},
			{
				"name":        "redis_exec",
				"description": "Execute a Redis command on a configured Redis instance. Results are automatically scanned and sensitive data is masked.",
				"inputSchema": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"database": map[string]interface{}{"type": "string", "description": "Redis name (configured via ZARA_REDIS_<NAME>_ADDR)"},
						"command":  map[string]interface{}{"type": "string", "description": "Redis command (GET, SET, HGETALL, LPUSH, etc.)"},
						"args":     map[string]interface{}{"type": "array", "description": "Command arguments", "items": map[string]interface{}{}},
					},
					"required": []string{"database", "command"},
				},
			},
			{
				"name":        "redis_keys",
				"description": "List Redis keys matching a pattern.",
				"inputSchema": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"database": map[string]interface{}{"type": "string", "description": "Redis name"},
						"pattern":  map[string]interface{}{"type": "string", "description": "Key pattern (e.g. 'user:*')", "default": "*"},
					},
					"required": []string{"database"},
				},
			},

			// ── HTTP API Tools (existing) ──
			{
				"name":        "http_request",
				"description": "Make an HTTP request to a configured API endpoint. Auth headers are injected automatically. Response body is scanned for secrets/PII and masked. Safer alternative to raw curl.",
				"inputSchema": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"api":     map[string]interface{}{"type": "string", "description": "API name (configured via ZARA_API_<NAME>_URL)"},
						"method":  map[string]interface{}{"type": "string", "description": "HTTP method (GET, POST, PUT, DELETE, PATCH)", "default": "GET"},
						"path":    map[string]interface{}{"type": "string", "description": "Request path (appended to base URL)"},
						"headers": map[string]interface{}{"type": "object", "description": "Additional request headers (optional)", "additionalProperties": map[string]string{"type": "string"}},
						"body":    map[string]interface{}{"description": "Request body (JSON, optional)"},
						"timeout": map[string]interface{}{"type": "integer", "description": "Timeout in seconds (default 30)", "default": 30},
					},
					"required": []string{"api", "path"},
				},
			},
			{
				"name":        "http_list_apis",
				"description": "List all configured HTTP API endpoints.",
				"inputSchema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
			},

			// ── AI Provider Tools ──
			{
				"name":        "ai_chat",
				"description": "Send a chat message to an AI provider. Your message is automatically redacted (secrets/PII replaced) before sending, and the response is unredacted before returning. Supports OpenAI, Anthropic, Gemini, DeepSeek, OpenRouter, and any OpenAI-compatible provider.",
				"inputSchema": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"provider": map[string]interface{}{"type": "string", "description": "AI provider name (configured via ZARA_AI_<NAME>_BASE_URL)"},
						"model":    map[string]interface{}{"type": "string", "description": "Model name (e.g. gpt-4o, claude-sonnet-4-20250514)"},
						"messages": map[string]interface{}{"type": "array", "description": "Chat messages", "items": map[string]interface{}{
							"type": "object",
							"properties": map[string]interface{}{
								"role":    map[string]interface{}{"type": "string", "description": "Message role: system, user, assistant"},
								"content": map[string]interface{}{"type": "string", "description": "Message content (auto-redacted before sending)"},
							},
						}},
					},
					"required": []string{"provider", "model", "messages"},
				},
			},
			{
				"name":        "ai_list_providers",
				"description": "List all configured AI providers and their available models.",
				"inputSchema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
			},

			// ── Config Tools ──
			{
				"name":        "config_list",
				"description": "List all configured connections (databases, APIs, AI providers). Shows status without exposing secrets.",
				"inputSchema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
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
	// ── Privacy Tools ──
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

	// ── Database Tools ──
	case "db_query":
		return s.callDBQuery(params.Arguments)
	case "db_list_tables":
		return s.callDBListTables(params.Arguments)
	case "db_describe":
		return s.callDBDescribe(params.Arguments)

	// ── MongoDB Tools ──
	case "mongo_find":
		return s.callMongoFind(params.Arguments)
	case "mongo_list_collections":
		return s.callMongoListCollections(params.Arguments)

	// ── Redis Tools ──
	case "redis_exec":
		return s.callRedisExec(params.Arguments)
	case "redis_keys":
		return s.callRedisKeys(params.Arguments)

	// ── HTTP API Tools ──
	case "http_request":
		return s.callHTTPRequest(params.Arguments)
	case "http_list_apis":
		return s.callHTTPListAPIs()

	// ── AI Provider Tools ──
	case "ai_chat":
		return s.callAIChat(params.Arguments)
	case "ai_list_providers":
		return s.callAIListProviders()

	// ── Config Tools ──
	case "config_list":
		return s.callConfigList()
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
		p.Locales = s.cfg.DefaultLocales
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
		p.Locales = s.cfg.DefaultLocales
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

// ═══════════════════════════════════════════════════════════════════════════
// Database Tool Handlers
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) callDBQuery(args json.RawMessage) (interface{}, *rpcError) {
	var p struct {
		Database string          `json:"database"`
		Query    string          `json:"query"`
		Params   json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return nil, &rpcError{Code: -32602, Message: "Invalid arguments"}
	}

	database, ok := s.dbRegistry.Get(p.Database)
	if !ok {
		return nil, &rpcError{Code: -32602, Message: "Unknown database: " + p.Database}
	}

	var result *db.QueryResult
	var err error

	upper := strings.TrimSpace(strings.ToUpper(p.Query))
	if strings.HasPrefix(upper, "SELECT") || strings.HasPrefix(upper, "WITH") || strings.HasPrefix(upper, "SHOW") || strings.HasPrefix(upper, "PRAGMA") {
		var params []interface{}
		if len(p.Params) > 0 {
			if err := json.Unmarshal(p.Params, &params); err != nil {
				// Treat as raw string params
				var strParams []string
				if err2 := json.Unmarshal(p.Params, &strParams); err2 == nil {
					for _, sp := range strParams {
						params = append(params, sp)
					}
				}
			}
		}
		result, err = database.Query(p.Query, params...)
	} else {
		var params []interface{}
		if len(p.Params) > 0 {
			if err := json.Unmarshal(p.Params, &params); err != nil {
				var strParams []string
				if err2 := json.Unmarshal(p.Params, &strParams); err2 == nil {
					for _, sp := range strParams {
						params = append(params, sp)
					}
				}
			}
		}
		result, err = database.Exec(p.Query, params...)
	}

	if err != nil {
		return nil, &rpcError{Code: -32603, Message: "Query error: " + err.Error()}
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

func (s *Server) callDBListTables(args json.RawMessage) (interface{}, *rpcError) {
	var p struct {
		Database string `json:"database"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return nil, &rpcError{Code: -32602, Message: "Invalid arguments"}
	}

	database, ok := s.dbRegistry.Get(p.Database)
	if !ok {
		return nil, &rpcError{Code: -32602, Message: "Unknown database: " + p.Database}
	}

	tables, err := database.ListTables()
	if err != nil {
		return nil, &rpcError{Code: -32603, Message: err.Error()}
	}

	return map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "json",
				"json": map[string]interface{}{
					"database": p.Database,
					"tables":   tables,
					"count":    len(tables),
				},
			},
		},
	}, nil
}

func (s *Server) callDBDescribe(args json.RawMessage) (interface{}, *rpcError) {
	var p struct {
		Database string `json:"database"`
		Table    string `json:"table"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return nil, &rpcError{Code: -32602, Message: "Invalid arguments"}
	}

	database, ok := s.dbRegistry.Get(p.Database)
	if !ok {
		return nil, &rpcError{Code: -32602, Message: "Unknown database: " + p.Database}
	}

	columns, err := database.DescribeTable(p.Table)
	if err != nil {
		return nil, &rpcError{Code: -32603, Message: err.Error()}
	}

	return map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "json",
				"json": map[string]interface{}{
					"database": p.Database,
					"table":    p.Table,
					"columns":  columns,
					"count":    len(columns),
				},
			},
		},
	}, nil
}

// ═══════════════════════════════════════════════════════════════════════════
// MongoDB Tool Handlers
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) callMongoFind(args json.RawMessage) (interface{}, *rpcError) {
	var p struct {
		Database   string                 `json:"database"`
		Collection string                 `json:"collection"`
		Filter     map[string]interface{} `json:"filter"`
		Limit      int64                  `json:"limit"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return nil, &rpcError{Code: -32602, Message: "Invalid arguments"}
	}
	if p.Limit <= 0 {
		p.Limit = 20
	}

	mdb, ok := s.mongoRegistry.Get(p.Database)
	if !ok {
		return nil, &rpcError{Code: -32602, Message: "Unknown MongoDB: " + p.Database}
	}

	filter := make(map[string]interface{})
	if p.Filter != nil {
		filter = p.Filter
	}

	result, err := mdb.Find(p.Collection, filter, p.Limit)
	if err != nil {
		return nil, &rpcError{Code: -32603, Message: err.Error()}
	}

	return map[string]interface{}{
		"content": []map[string]interface{}{{"type": "json", "json": result}},
	}, nil
}

func (s *Server) callMongoListCollections(args json.RawMessage) (interface{}, *rpcError) {
	var p struct {
		Database string `json:"database"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return nil, &rpcError{Code: -32602, Message: "Invalid arguments"}
	}

	mdb, ok := s.mongoRegistry.Get(p.Database)
	if !ok {
		return nil, &rpcError{Code: -32602, Message: "Unknown MongoDB: " + p.Database}
	}

	cols, err := mdb.ListCollections()
	if err != nil {
		return nil, &rpcError{Code: -32603, Message: err.Error()}
	}

	return map[string]interface{}{
		"content": []map[string]interface{}{{"type": "json", "json": map[string]interface{}{
			"database":    p.Database,
			"collections": cols,
			"count":       len(cols),
		}}},
	}, nil
}

// ═══════════════════════════════════════════════════════════════════════════
// Redis Tool Handlers
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) callRedisExec(args json.RawMessage) (interface{}, *rpcError) {
	var p struct {
		Database string        `json:"database"`
		Command  string        `json:"command"`
		Args     []interface{} `json:"args"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return nil, &rpcError{Code: -32602, Message: "Invalid arguments"}
	}

	rdb, ok := s.redisRegistry.Get(p.Database)
	if !ok {
		return nil, &rpcError{Code: -32602, Message: "Unknown Redis: " + p.Database}
	}

	result, err := rdb.Do(p.Command, p.Args...)
	if err != nil {
		return nil, &rpcError{Code: -32603, Message: err.Error()}
	}

	return map[string]interface{}{
		"content": []map[string]interface{}{{"type": "json", "json": result}},
	}, nil
}

func (s *Server) callRedisKeys(args json.RawMessage) (interface{}, *rpcError) {
	var p struct {
		Database string `json:"database"`
		Pattern  string `json:"pattern"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return nil, &rpcError{Code: -32602, Message: "Invalid arguments"}
	}
	if p.Pattern == "" {
		p.Pattern = "*"
	}

	rdb, ok := s.redisRegistry.Get(p.Database)
	if !ok {
		return nil, &rpcError{Code: -32602, Message: "Unknown Redis: " + p.Database}
	}

	keys, err := rdb.Keys(p.Pattern)
	if err != nil {
		return nil, &rpcError{Code: -32603, Message: err.Error()}
	}

	return map[string]interface{}{
		"content": []map[string]interface{}{{"type": "json", "json": map[string]interface{}{
			"database": p.Database,
			"pattern":  p.Pattern,
			"keys":     keys,
			"count":    len(keys),
		}}},
	}, nil
}

// ═══════════════════════════════════════════════════════════════════════════
// HTTP API Tool Handlers
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) callHTTPRequest(args json.RawMessage) (interface{}, *rpcError) {
	var p struct {
		API     string          `json:"api"`
		Method  string          `json:"method"`
		Path    string          `json:"path"`
		Headers map[string]string `json:"headers"`
		Body    json.RawMessage `json:"body"`
		Timeout int             `json:"timeout"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return nil, &rpcError{Code: -32602, Message: "Invalid arguments"}
	}

	if p.Method == "" {
		p.Method = "GET"
	}
	if p.Timeout <= 0 {
		p.Timeout = 30
	}

	req := httpproxy.Request{
		Method:  p.Method,
		Path:    p.Path,
		Headers: p.Headers,
		Body:    p.Body,
		Timeout: p.Timeout,
	}

	resp, err := s.apiRegistry.Do(p.API, req)
	if err != nil {
		return nil, &rpcError{Code: -32603, Message: err.Error()}
	}

	return map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "json",
				"json": resp,
			},
		},
	}, nil
}

func (s *Server) callHTTPListAPIs() (interface{}, *rpcError) {
	apis := s.apiRegistry.List()
	return map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "json",
				"json": map[string]interface{}{
					"apis":  apis,
					"count": len(apis),
				},
			},
		},
	}, nil
}

// ═══════════════════════════════════════════════════════════════════════════
// AI Provider Tool Handlers
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) callAIChat(args json.RawMessage) (interface{}, *rpcError) {
	var p struct {
		Provider string          `json:"provider"`
		Model    string          `json:"model"`
		Messages json.RawMessage `json:"messages"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return nil, &rpcError{Code: -32602, Message: "Invalid arguments"}
	}

	var messages []ai.ChatMessage
	if err := json.Unmarshal(p.Messages, &messages); err != nil {
		return nil, &rpcError{Code: -32602, Message: "Invalid messages: " + err.Error()}
	}

	chatReq := ai.ChatRequest{
		Model:    p.Model,
		Messages: messages,
	}

	response, err := s.aiRegistry.Chat(p.Provider, chatReq, s.engine)
	if err != nil {
		return nil, &rpcError{Code: -32603, Message: err.Error()}
	}

	return map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "json",
				"json": response,
			},
		},
	}, nil
}

func (s *Server) callAIListProviders() (interface{}, *rpcError) {
	providers := s.aiRegistry.List()
	details := make([]map[string]interface{}, 0)
	for _, name := range providers {
		p, _ := s.aiRegistry.Get(name)
		details = append(details, map[string]interface{}{
			"name":      name,
			"base_url":  p.BaseURL,
			"configured": p.APIKey != "",
			"models":    p.Models,
		})
	}

	return map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "json",
				"json": map[string]interface{}{
					"providers": details,
					"count":     len(details),
				},
			},
		},
	}, nil
}

// ═══════════════════════════════════════════════════════════════════════════
// Config Tool Handlers
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) callConfigList() (interface{}, *rpcError) {
	databases := make([]map[string]interface{}, 0)
	for _, dbc := range s.appConfig.Databases {
		databases = append(databases, map[string]interface{}{
			"name":   dbc.Name,
			"driver": dbc.Driver,
			"status": "connected",
		})
	}

	apis := make([]map[string]interface{}, 0)
	for _, apic := range s.appConfig.APIs {
		hasAuth := apic.AuthEnv != ""
		apis = append(apis, map[string]interface{}{
			"name":    apic.Name,
			"base_url": apic.BaseURL,
			"auth":    apic.AuthType,
			"authenticated": hasAuth,
		})
	}

	aiProvs := make([]map[string]interface{}, 0)
	for _, aic := range s.appConfig.AIProviders {
		aiProvs = append(aiProvs, map[string]interface{}{
			"name":      aic.Name,
			"base_url":  aic.BaseURL,
			"configured": aic.APIKey != "",
			"models":    aic.Models,
		})
	}

	return map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "json",
				"json": map[string]interface{}{
					"databases":    databases,
					"apis":         apis,
					"ai_providers": aiProvs,
				},
			},
		},
	}, nil
}

// ---------------------------------------------------------------------------
// Stdio Transport
// ---------------------------------------------------------------------------

// StartStdio reads JSON-RPC requests from stdin and writes responses to stdout.
// Each line is a separate JSON-RPC request (newline-delimited JSON).
func (s *Server) StartStdio() error {
	log.Println("[Zara Privacy MCP] Starting stdio transport...")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1MB buffer

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		resp := s.ServeMessage(line)
		if resp == nil {
			continue
		}
		fmt.Println(string(resp))
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("stdin error: %w", err)
	}
	return io.EOF
}

// marshalResponse serializes a JSON-RPC response to bytes.
func (s *Server) marshalResponse(id *json.RawMessage, result interface{}, rpcErr *rpcError) []byte {
	resp := rpcResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
		Error:   rpcErr,
	}
	b, err := json.Marshal(resp)
	if err != nil {
		log.Printf("Error marshaling response: %v", err)
		return nil
	}
	return b
}

// writeResponse sends a JSON-RPC response over HTTP.
func (s *Server) writeResponse(w http.ResponseWriter, id *json.RawMessage, result interface{}, rpcErr *rpcError) {
	w.Header().Set("Content-Type", "application/json")
	b := s.marshalResponse(id, result, rpcErr)
	if b != nil {
		w.Write(b)
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
