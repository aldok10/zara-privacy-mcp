package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/aldok10/zara-privacy-mcp/config"
	"github.com/aldok10/zara-privacy-mcp/internal/ai"
	"github.com/aldok10/zara-privacy-mcp/internal/audit"
	"github.com/aldok10/zara-privacy-mcp/internal/classify"
	"github.com/aldok10/zara-privacy-mcp/internal/compress"
	"github.com/aldok10/zara-privacy-mcp/internal/db"
	"github.com/aldok10/zara-privacy-mcp/internal/detector"
	"github.com/aldok10/zara-privacy-mcp/internal/engine"
	httpproxy "github.com/aldok10/zara-privacy-mcp/internal/http"
	"github.com/aldok10/zara-privacy-mcp/internal/store"
	"github.com/aldok10/zara-privacy-mcp/internal/version"
)

// Handlers holds all MCP tool handler methods.
type Handlers struct {
	Engine         *engine.RedactEngine
	Compressor     *compress.Compressor
	Classifier     *classify.Classifier
	Store          *store.MappingStore
	DBRegistry     *db.Registry
	MongoRegistry  *db.MongoRegistry
	RedisRegistry  *db.RedisRegistry
	APIRegistry    *httpproxy.Registry
	AIRegistry     *ai.Registry
	AIRouter       *ai.Router // optional: fallback routing
	AuditLog       *audit.Logger
	AppConfig      *config.Config
	DefaultLocales []string
	MaxTextSize    int
}

const maxTextSize = 1024 * 1024 // 1MB

// ─── Privacy Tools ──────────────────────────────────────────────────────────

func (h *Handlers) ScanContext(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	text, err := req.RequireString("text")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	if len(text) > maxTextSize {
		return mcp.NewToolResultError("text exceeds maximum size (1MB)"), nil
	}

	locales := h.getLocales(req)
	result := h.Engine.ScanContext(text, locales...)
	return jsonResult(result)
}

func (h *Handlers) RedactContext(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	text, err := req.RequireString("text")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	if len(text) > maxTextSize {
		return mcp.NewToolResultError("text exceeds maximum size (1MB)"), nil
	}

	locales := h.getLocales(req)
	result := h.Engine.RedactContext(text, locales...)
	return jsonResult(result)
}

func (h *Handlers) UnredactResponse(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	text, err := req.RequireString("text")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	restored := h.Engine.UnredactResponse(text)
	return mcp.NewToolResultText(restored), nil
}

func (h *Handlers) CompressContext(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	text, err := req.RequireString("text")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	keywords := getStringSlice(req, "keywords")
	compressed := h.Compressor.Compress(text, keywords)
	before := estimateTokens(text)
	after := estimateTokens(compressed)

	return jsonResult(map[string]any{
		"compressed":   compressed,
		"tokens_saved": before - after,
	})
}

func (h *Handlers) MemoryFilter(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	text, err := req.RequireString("text")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	scanResult := h.Engine.ScanContext(text)

	// Guard: if risk is below threshold, allow immediately
	if scanResult.RiskScore < detector.RiskHigh {
		return jsonResult(map[string]any{
			"allowed": true,
			"reason":  "",
			"blocked": []string{},
		})
	}

	// High risk — collect blocked types
	var blocked []string
	for _, f := range scanResult.SecretsFound {
		if f.Risk >= detector.RiskHigh {
			blocked = append(blocked, f.Type)
		}
	}

	return jsonResult(map[string]any{
		"allowed": false,
		"reason":  "Contains high-risk sensitive data",
		"blocked": blocked,
	})
}

func (h *Handlers) ClassifyData(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	text, err := req.RequireString("text")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	scanResult := h.Engine.ScanContext(text)
	classification := h.Classifier.Classify(text, scanResult)
	return jsonResult(classification)
}

func (h *Handlers) StoreStats(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	stats := h.Store.Stats()
	return jsonResult(stats)
}

// ─── Database Tools ─────────────────────────────────────────────────────────

func (h *Handlers) DBQuery(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	dbName, err := req.RequireString("database")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	query, err := req.RequireString("query")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Security gate
	if err := validateSQL(query); err != nil {
		h.AuditLog.LogBlocked("db_query", err.Error())
		return mcp.NewToolResultError("blocked: " + err.Error()), nil
	}

	database, ok := h.DBRegistry.Get(dbName)
	if !ok {
		return mcp.NewToolResultError("unknown database: " + dbName), nil
	}

	var params []any
	if args := req.GetArguments(); args["params"] != nil {
		if p, ok := args["params"].([]any); ok {
			params = p
		}
	}

	upper := strings.TrimSpace(strings.ToUpper(query))
	var result *db.QueryResult
	if isReadQuery(upper) {
		result, err = database.Query(ctx, query, params...)
	} else {
		result, err = database.Exec(ctx, query, params...)
	}
	if err != nil {
		return mcp.NewToolResultError("query execution failed"), nil
	}

	return jsonResult(result)
}

func (h *Handlers) DBListTables(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	dbName, err := req.RequireString("database")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	database, ok := h.DBRegistry.Get(dbName)
	if !ok {
		return mcp.NewToolResultError("unknown database: " + dbName), nil
	}

	tables, err := database.ListTables()
	if err != nil {
		return mcp.NewToolResultError("failed to list tables"), nil
	}

	return jsonResult(map[string]any{
		"database": dbName,
		"tables":   tables,
		"count":    len(tables),
	})
}

func (h *Handlers) DBDescribe(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	dbName, err := req.RequireString("database")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	table, err := req.RequireString("table")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	database, ok := h.DBRegistry.Get(dbName)
	if !ok {
		return mcp.NewToolResultError("unknown database: " + dbName), nil
	}

	columns, err := database.DescribeTable(table)
	if err != nil {
		return mcp.NewToolResultError("failed to describe table"), nil
	}

	return jsonResult(map[string]any{
		"database": dbName,
		"table":    table,
		"columns":  columns,
		"count":    len(columns),
	})
}

// ─── MongoDB Tools ──────────────────────────────────────────────────────────

func (h *Handlers) MongoFind(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	dbName, err := req.RequireString("database")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	collection, err := req.RequireString("collection")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	mdb, ok := h.MongoRegistry.Get(dbName)
	if !ok {
		return mcp.NewToolResultError("unknown MongoDB: " + dbName), nil
	}

	args := req.GetArguments()
	filter := make(map[string]any)
	if f, ok := args["filter"].(map[string]any); ok {
		filter = f
	}

	// Security gate
	if err := validateMongoFilter(filter); err != nil {
		h.AuditLog.LogBlocked("mongo_find", err.Error())
		return mcp.NewToolResultError("blocked: " + err.Error()), nil
	}

	limit := int64(20)
	if l, ok := args["limit"].(float64); ok && l > 0 {
		limit = int64(l)
	}

	result, err := mdb.Find(ctx, collection, filter, limit)
	if err != nil {
		return mcp.NewToolResultError("query execution failed"), nil
	}

	return jsonResult(result)
}

func (h *Handlers) MongoListCollections(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	dbName, err := req.RequireString("database")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	mdb, ok := h.MongoRegistry.Get(dbName)
	if !ok {
		return mcp.NewToolResultError("unknown MongoDB: " + dbName), nil
	}

	cols, err := mdb.ListCollections(ctx)
	if err != nil {
		return mcp.NewToolResultError("failed to list collections"), nil
	}

	return jsonResult(map[string]any{
		"database":    dbName,
		"collections": cols,
		"count":       len(cols),
	})
}

// ─── Redis Tools ────────────────────────────────────────────────────────────

func (h *Handlers) RedisExec(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	dbName, err := req.RequireString("database")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	command, err := req.RequireString("command")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Security gate
	if err := validateRedisCommand(command); err != nil {
		h.AuditLog.LogBlocked("redis_exec", err.Error())
		return mcp.NewToolResultError("blocked: " + err.Error()), nil
	}

	rdb, ok := h.RedisRegistry.Get(dbName)
	if !ok {
		return mcp.NewToolResultError("unknown Redis: " + dbName), nil
	}

	var args []any
	if a := req.GetArguments()["args"]; a != nil {
		if arr, ok := a.([]any); ok {
			args = arr
		}
	}

	result, err := rdb.Do(ctx, command, args...)
	if err != nil {
		return mcp.NewToolResultError("command execution failed"), nil
	}

	return jsonResult(result)
}

func (h *Handlers) RedisKeys(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	dbName, err := req.RequireString("database")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	rdb, ok := h.RedisRegistry.Get(dbName)
	if !ok {
		return mcp.NewToolResultError("unknown Redis: " + dbName), nil
	}

	pattern := "user:*" // safe default instead of "*"
	if p, ok := req.GetArguments()["pattern"].(string); ok && p != "" {
		pattern = p
	}

	keys, err := rdb.Keys(ctx, pattern)
	if err != nil {
		return mcp.NewToolResultError("failed to list keys"), nil
	}

	return jsonResult(map[string]any{
		"database": dbName,
		"pattern":  pattern,
		"keys":     keys,
		"count":    len(keys),
	})
}

// ─── HTTP API Tools ─────────────────────────────────────────────────────────

func (h *Handlers) HTTPRequest(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	apiName, err := req.RequireString("api")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	path, err := req.RequireString("path")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	args := req.GetArguments()
	method := "GET"
	if m, ok := args["method"].(string); ok && m != "" {
		method = m
	}
	timeout := 30
	if t, ok := args["timeout"].(float64); ok && t > 0 && t <= 120 {
		timeout = int(t)
	}

	var headers map[string]string
	if h2, ok := args["headers"].(map[string]any); ok {
		headers = make(map[string]string)
		for k, v := range h2 {
			headers[k] = fmt.Sprintf("%v", v)
		}
	}

	var body json.RawMessage
	if b, ok := args["body"].(string); ok && b != "" {
		body = json.RawMessage(b)
	}

	proxyReq := httpproxy.Request{
		Method:  method,
		Path:    path,
		Headers: headers,
		Body:    body,
		Timeout: timeout,
	}

	resp, err := h.APIRegistry.Do(ctx, apiName, proxyReq)
	if err != nil {
		return mcp.NewToolResultError("request failed"), nil
	}

	return jsonResult(resp)
}

func (h *Handlers) HTTPListAPIs(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	apis := h.APIRegistry.List()
	return jsonResult(map[string]any{
		"apis":  apis,
		"count": len(apis),
	})
}

// ─── AI Provider Tools ──────────────────────────────────────────────────────

func (h *Handlers) AIChat(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	providerName, err := req.RequireString("provider")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	model, err := req.RequireString("model")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	args := req.GetArguments()
	messagesRaw, ok := args["messages"]
	if !ok {
		return mcp.NewToolResultError("messages is required"), nil
	}

	msgBytes, err := json.Marshal(messagesRaw)
	if err != nil {
		return mcp.NewToolResultError("invalid messages"), nil
	}
	var messages []ai.ChatMessage
	if err := json.Unmarshal(msgBytes, &messages); err != nil {
		return mcp.NewToolResultError("invalid messages format"), nil
	}

	chatReq := ai.ChatRequest{
		Model:    model,
		Messages: messages,
	}

	// Use router with fallback if configured, otherwise direct
	var response *ai.ChatResponse
	if h.AIRouter != nil {
		response, err = h.AIRouter.ChatWithFallback(providerName, chatReq)
	} else {
		response, err = h.AIRegistry.Chat(providerName, chatReq, h.Engine)
	}
	if err != nil {
		return mcp.NewToolResultError("AI request failed"), nil
	}

	return jsonResult(response)
}

func (h *Handlers) AIListProviders(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	providers := h.AIRegistry.List()
	details := make([]map[string]any, 0)
	for _, name := range providers {
		p, _ := h.AIRegistry.Get(name)
		details = append(details, map[string]any{
			"name":       name,
			"base_url":   p.BaseURL,
			"configured": p.APIKey != "",
			"models":     p.Models,
		})
	}

	return jsonResult(map[string]any{
		"providers": details,
		"count":     len(details),
	})
}

func (h *Handlers) AIQuotaStatus(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if h.AIRouter == nil {
		return jsonResult(map[string]any{"quota": map[string]any{}, "usage": []any{}})
	}
	return jsonResult(map[string]any{
		"quota": h.AIRouter.Quota().Status(),
		"usage": h.AIRouter.Stats(),
	})
}

// ─── Config Tools ───────────────────────────────────────────────────────────

func (h *Handlers) ConfigList(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	databases := make([]map[string]any, 0)
	for _, dbc := range h.AppConfig.Databases {
		databases = append(databases, map[string]any{
			"name":   dbc.Name,
			"driver": dbc.Driver,
			"status": "connected",
		})
	}

	apis := make([]map[string]any, 0)
	for _, apic := range h.AppConfig.APIs {
		apis = append(apis, map[string]any{
			"name":     apic.Name,
			"base_url": apic.BaseURL,
			"auth":     apic.AuthType,
		})
	}

	aiProvs := make([]map[string]any, 0)
	for _, aic := range h.AppConfig.AIProviders {
		aiProvs = append(aiProvs, map[string]any{
			"name":       aic.Name,
			"base_url":   aic.BaseURL,
			"configured": aic.APIKey != "",
			"models":     aic.Models,
		})
	}

	return jsonResult(map[string]any{
		"databases":    databases,
		"apis":         apis,
		"ai_providers": aiProvs,
	})
}

func (h *Handlers) Version(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return jsonResult(map[string]any{
		"version": version.Version,
		"commit":  version.Commit,
		"date":    version.Date,
	})
}

// ─── Helpers ────────────────────────────────────────────────────────────────

func jsonResult(v any) (*mcp.CallToolResult, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return mcp.NewToolResultError("failed to serialize result"), nil
	}
	return mcp.NewToolResultText(string(b)), nil
}

func (h *Handlers) getLocales(req mcp.CallToolRequest) []string {
	locales := getStringSlice(req, "locales")
	if len(locales) == 0 {
		return h.DefaultLocales
	}
	return locales
}

func getStringSlice(req mcp.CallToolRequest, key string) []string {
	args := req.GetArguments()
	if arr, ok := args[key].([]any); ok {
		var result []string
		for _, v := range arr {
			if s, ok := v.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

func estimateTokens(s string) int {
	if s == "" {
		return 0
	}
	return len(strings.Fields(s)) + (len(s) / 4)
}
