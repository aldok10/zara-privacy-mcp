package transport

import (
	"context"
	"log"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/aldok10/zara-privacy-mcp/application/tools"
	"github.com/aldok10/zara-privacy-mcp/internal/observe"
	"github.com/aldok10/zara-privacy-mcp/internal/version"
)

// MCPServer wraps the mcp-go server.
type MCPServer struct {
	s *server.MCPServer
}

// Server returns the underlying mcp-go server.
func (m *MCPServer) Server() *server.MCPServer { return m.s }

// NewMCPServer creates the MCP server with all 19 tools registered.
func NewMCPServer(handlers *tools.Handlers, obs *observe.Client) *MCPServer {
	s := server.NewMCPServer(
		"zara-privacy-mcp",
		version.Version,
		server.WithToolCapabilities(false),
		server.WithRecovery(),
		server.WithHooks(&server.Hooks{
			OnAfterCallTool: []server.OnAfterCallToolFunc{
				func(ctx context.Context, id any, req *mcp.CallToolRequest, res any) {
					log.Printf("[TOOL] %s completed", req.Params.Name)
				},
			},
		}),
		server.WithToolHandlerMiddleware(rateLimitMiddleware(20)),
		server.WithToolHandlerMiddleware(observeMiddleware(obs)),
		server.WithToolHandlerMiddleware(auditMiddleware),
	)

	registerPrivacyTools(s, handlers)
	registerDatabaseTools(s, handlers)
	registerMongoTools(s, handlers)
	registerRedisTools(s, handlers)
	registerHTTPTools(s, handlers)
	registerAITools(s, handlers)
	registerConfigTools(s, handlers)

	return &MCPServer{s: s}
}

// ─── Privacy Tools ──────────────────────────────────────────────────────────

func registerPrivacyTools(s *server.MCPServer, h *tools.Handlers) {
	s.AddTool(
		mcp.NewTool("scan_context",
			mcp.WithDescription("Scan conversation context for secrets and PII. Returns risk score, findings, and recommendation without modifying the text."),
			mcp.WithString("text", mcp.Required(), mcp.Description("The context text to scan")),
			mcp.WithArray("locales", mcp.Description("Locale filters (id, sg, global)")),
		),
		h.ScanContext,
	)

	s.AddTool(
		mcp.NewTool("redact_context",
			mcp.WithDescription("Replace detected secrets and PII with reversible placeholders. Returns redacted text safe to send to LLM providers."),
			mcp.WithString("text", mcp.Required(), mcp.Description("The context text to redact")),
			mcp.WithArray("locales", mcp.Description("Locale filters for PII detection")),
		),
		h.RedactContext,
	)

	s.AddTool(
		mcp.NewTool("unredact_response",
			mcp.WithDescription("Restore original values in an LLM response by replacing placeholders with original data."),
			mcp.WithString("text", mcp.Required(), mcp.Description("The LLM response text containing placeholders")),
		),
		h.UnredactResponse,
	)

	s.AddTool(
		mcp.NewTool("compress_context",
			mcp.WithDescription("Compress context to reduce token usage. Deduplicates lines, removes comments, optionally extracts relevant sections."),
			mcp.WithString("text", mcp.Required(), mcp.Description("The context text to compress")),
			mcp.WithArray("keywords", mcp.Description("Keywords for relevance extraction (optional)")),
		),
		h.CompressContext,
	)

	s.AddTool(
		mcp.NewTool("memory_filter",
			mcp.WithDescription("Validate memory content before persistence. Blocks sensitive data from being stored in conversation memory."),
			mcp.WithString("text", mcp.Required(), mcp.Description("Memory content to validate")),
		),
		h.MemoryFilter,
	)

	s.AddTool(
		mcp.NewTool("classify_data",
			mcp.WithDescription("Classify data by sensitivity level (PUBLIC, INTERNAL, CONFIDENTIAL, SECRET). Uses scan results and content analysis."),
			mcp.WithString("text", mcp.Required(), mcp.Description("The data to classify")),
		),
		h.ClassifyData,
	)

	s.AddTool(
		mcp.NewTool("store_stats",
			mcp.WithDescription("Get statistics about the placeholder mapping store."),
		),
		h.StoreStats,
	)
}

// ─── Database Tools ─────────────────────────────────────────────────────────

func registerDatabaseTools(s *server.MCPServer, h *tools.Handlers) {
	s.AddTool(
		mcp.NewTool("db_query",
			mcp.WithDescription("Execute a SQL query on a configured database. Results are automatically scanned and sensitive data is masked."),
			mcp.WithString("database", mcp.Required(), mcp.Description("Database name (configured via ZARA_DB_<NAME>_DSN)")),
			mcp.WithString("query", mcp.Required(), mcp.Description("SQL query to execute")),
			mcp.WithArray("params", mcp.Description("Query parameters (optional)")),
		),
		h.DBQuery,
	)

	s.AddTool(
		mcp.NewTool("db_list_tables",
			mcp.WithDescription("List all tables in a configured database."),
			mcp.WithString("database", mcp.Required(), mcp.Description("Database name")),
		),
		h.DBListTables,
	)

	s.AddTool(
		mcp.NewTool("db_describe",
			mcp.WithDescription("Describe a table's schema (columns, types, nullability)."),
			mcp.WithString("database", mcp.Required(), mcp.Description("Database name")),
			mcp.WithString("table", mcp.Required(), mcp.Description("Table name")),
		),
		h.DBDescribe,
	)
}

// ─── MongoDB Tools ──────────────────────────────────────────────────────────

func registerMongoTools(s *server.MCPServer, h *tools.Handlers) {
	s.AddTool(
		mcp.NewTool("mongo_find",
			mcp.WithDescription("Query documents from a configured MongoDB collection. Results are automatically scanned and sensitive data is masked."),
			mcp.WithString("database", mcp.Required(), mcp.Description("MongoDB name (configured via ZARA_MONGO_<NAME>_URI)")),
			mcp.WithString("collection", mcp.Required(), mcp.Description("Collection name")),
			mcp.WithObject("filter", mcp.Description("MongoDB filter (JSON object, optional)")),
			mcp.WithNumber("limit", mcp.Description("Max documents to return (default 20)")),
		),
		h.MongoFind,
	)

	s.AddTool(
		mcp.NewTool("mongo_list_collections",
			mcp.WithDescription("List all collections in a configured MongoDB database."),
			mcp.WithString("database", mcp.Required(), mcp.Description("MongoDB name")),
		),
		h.MongoListCollections,
	)
}

// ─── Redis Tools ────────────────────────────────────────────────────────────

func registerRedisTools(s *server.MCPServer, h *tools.Handlers) {
	s.AddTool(
		mcp.NewTool("redis_exec",
			mcp.WithDescription("Execute a Redis command on a configured Redis instance. Results are automatically scanned and sensitive data is masked."),
			mcp.WithString("database", mcp.Required(), mcp.Description("Redis name (configured via ZARA_REDIS_<NAME>_ADDR)")),
			mcp.WithString("command", mcp.Required(), mcp.Description("Redis command (GET, SET, HGETALL, LPUSH, etc.)")),
			mcp.WithArray("args", mcp.Description("Command arguments")),
		),
		h.RedisExec,
	)

	s.AddTool(
		mcp.NewTool("redis_keys",
			mcp.WithDescription("List Redis keys matching a pattern."),
			mcp.WithString("database", mcp.Required(), mcp.Description("Redis name")),
			mcp.WithString("pattern", mcp.Description("Key pattern (e.g. 'user:*')")),
		),
		h.RedisKeys,
	)
}

// ─── HTTP API Tools ─────────────────────────────────────────────────────────

func registerHTTPTools(s *server.MCPServer, h *tools.Handlers) {
	s.AddTool(
		mcp.NewTool("http_request",
			mcp.WithDescription("Make an HTTP request to a configured API endpoint. Auth headers are injected automatically. Response body is scanned for secrets/PII and masked."),
			mcp.WithString("api", mcp.Required(), mcp.Description("API name (configured via ZARA_API_<NAME>_URL)")),
			mcp.WithString("path", mcp.Required(), mcp.Description("Request path (appended to base URL)")),
			mcp.WithString("method", mcp.Description("HTTP method (GET, POST, PUT, DELETE, PATCH)")),
			mcp.WithObject("headers", mcp.Description("Additional request headers (optional)")),
			mcp.WithString("body", mcp.Description("Request body (JSON string, optional)")),
			mcp.WithNumber("timeout", mcp.Description("Timeout in seconds (default 30)")),
		),
		h.HTTPRequest,
	)

	s.AddTool(
		mcp.NewTool("http_list_apis",
			mcp.WithDescription("List all configured HTTP API endpoints."),
		),
		h.HTTPListAPIs,
	)
}

// ─── AI Provider Tools ──────────────────────────────────────────────────────

func registerAITools(s *server.MCPServer, h *tools.Handlers) {
	s.AddTool(
		mcp.NewTool("ai_chat",
			mcp.WithDescription("Send a chat message to an AI provider. Your message is automatically redacted before sending, and the response is unredacted before returning."),
			mcp.WithString("provider", mcp.Required(), mcp.Description("AI provider name (configured via ZARA_AI_<NAME>_BASE_URL)")),
			mcp.WithString("model", mcp.Required(), mcp.Description("Model name (e.g. gpt-4o, claude-sonnet-4-20250514)")),
			mcp.WithArray("messages", mcp.Required(), mcp.Description("Chat messages [{role, content}]")),
		),
		h.AIChat,
	)

	s.AddTool(
		mcp.NewTool("ai_list_providers",
			mcp.WithDescription("List all configured AI providers and their available models."),
		),
		h.AIListProviders,
	)

	s.AddTool(
		mcp.NewTool("ai_quota_status",
			mcp.WithDescription("Show AI provider quota usage and statistics. Includes token usage per provider and remaining quota."),
		),
		h.AIQuotaStatus,
	)
}

// ─── Config Tools ───────────────────────────────────────────────────────────

func registerConfigTools(s *server.MCPServer, h *tools.Handlers) {
	s.AddTool(
		mcp.NewTool("config_list",
			mcp.WithDescription("List all configured connections (databases, APIs, AI providers). Shows status without exposing secrets."),
		),
		h.ConfigList,
	)
}

// ─── Middleware ──────────────────────────────────────────────────────────────

// auditMiddleware logs tool execution duration.
func auditMiddleware(next server.ToolHandlerFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		result, err := next(ctx, req)
		log.Printf("[AUDIT] tool=%s duration=%s", req.Params.Name, time.Since(start).Round(time.Millisecond))
		return result, err
	}
}

// rateLimitMiddleware prevents runaway tool calls.
// Allows max concurrent calls; excess returns an error.
func rateLimitMiddleware(maxConcurrent int) server.ToolHandlerMiddleware {
	sem := make(chan struct{}, maxConcurrent)
	return func(next server.ToolHandlerFunc) server.ToolHandlerFunc {
		return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
				return next(ctx, req)
			default:
				return mcp.NewToolResultError("rate limited: too many concurrent requests"), nil
			}
		}
	}
}

// observeMiddleware sends tool call telemetry to OpenObserve.
func observeMiddleware(obs *observe.Client) server.ToolHandlerMiddleware {
	return func(next server.ToolHandlerFunc) server.ToolHandlerFunc {
		return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			start := time.Now()
			result, err := next(ctx, req)
			status := "ok"
			if err != nil || (result != nil && result.IsError) {
				status = "error"
			}
			obs.LogTool(req.Params.Name, time.Since(start), status, 0)
			return result, err
		}
	}
}
