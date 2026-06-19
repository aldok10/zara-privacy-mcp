package tools

import (
	"context"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/aldok10/zara-privacy-mcp/config"
	"github.com/aldok10/zara-privacy-mcp/internal/ai"
	"github.com/aldok10/zara-privacy-mcp/internal/classify"
	"github.com/aldok10/zara-privacy-mcp/internal/compress"
	"github.com/aldok10/zara-privacy-mcp/internal/db"
	"github.com/aldok10/zara-privacy-mcp/internal/detector"
	"github.com/aldok10/zara-privacy-mcp/internal/engine"
	httpproxy "github.com/aldok10/zara-privacy-mcp/internal/http"
	"github.com/aldok10/zara-privacy-mcp/internal/store"
)

func newTestHandlers(t *testing.T) *Handlers {
	t.Helper()
	sd := detector.NewSecretDetector()
	pd := detector.NewPIIDetector()
	ms, err := store.NewMappingStore(t.TempDir()+"/test.db", []byte("test-key-32-bytes-long-minimum!!"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ms.Close() })

	return &Handlers{
		Engine:         engine.NewRedactEngine(sd, pd, ms),
		Compressor:     compress.NewCompressor(4096),
		Classifier:     classify.NewClassifier(),
		Store:          ms,
		DBRegistry:     db.NewRegistry(),
		MongoRegistry:  db.NewMongoRegistry(),
		RedisRegistry:  db.NewRedisRegistry(),
		APIRegistry:    httpproxy.NewRegistry(sd, pd),
		AIRegistry:     ai.NewRegistry(),
		AIRouter:       ai.NewRouter(ai.NewRegistry(), engine.NewRedactEngine(sd, pd, ms), ai.RouterConfig{MaxRetries: 1}),
		AppConfig:      &config.Config{Databases: make(map[string]config.DBConfig)},
		DefaultLocales: []string{"id", "sg", "global"},
	}
}

func makeReq(name string, args map[string]any) mcp.CallToolRequest {
	req := mcp.CallToolRequest{}
	req.Params.Name = name
	req.Params.Arguments = args
	return req
}

func TestHandlers_ScanContext(t *testing.T) {
	h := newTestHandlers(t)
	tests := []struct {
		name    string
		args    map[string]any
		wantErr bool
	}{
		{name: "valid text", args: map[string]any{"text": "hello@test.com"}, wantErr: false},
		{name: "missing text", args: map[string]any{}, wantErr: true},
		{name: "oversized text", args: map[string]any{"text": string(make([]byte, 2*1024*1024))}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _ := h.ScanContext(context.Background(), makeReq("scan_context", tt.args))
			if result.IsError != tt.wantErr {
				t.Errorf("IsError = %v; want %v", result.IsError, tt.wantErr)
			}
		})
	}
}

func TestHandlers_RedactContext(t *testing.T) {
	h := newTestHandlers(t)
	result, _ := h.RedactContext(context.Background(), makeReq("redact_context", map[string]any{"text": "key sk-proj-abc123def456"}))
	if result.IsError {
		t.Error("unexpected error")
	}
}

func TestHandlers_UnredactResponse(t *testing.T) {
	h := newTestHandlers(t)
	result, _ := h.UnredactResponse(context.Background(), makeReq("unredact_response", map[string]any{"text": "hello [EMAIL_1]"}))
	if result.IsError {
		t.Error("unexpected error")
	}
}

func TestHandlers_CompressContext(t *testing.T) {
	h := newTestHandlers(t)
	result, _ := h.CompressContext(context.Background(), makeReq("compress_context", map[string]any{"text": "line1\nline1\nline2"}))
	if result.IsError {
		t.Error("unexpected error")
	}
}

func TestHandlers_MemoryFilter(t *testing.T) {
	h := newTestHandlers(t)
	tests := []struct {
		name string
		text string
	}{
		{name: "safe text", text: "hello world"},
		{name: "with pii", text: "email: test@x.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _ := h.MemoryFilter(context.Background(), makeReq("memory_filter", map[string]any{"text": tt.text}))
			if result.IsError {
				t.Error("unexpected error")
			}
		})
	}
}

func TestHandlers_ClassifyData(t *testing.T) {
	h := newTestHandlers(t)
	result, _ := h.ClassifyData(context.Background(), makeReq("classify_data", map[string]any{"text": "public info"}))
	if result.IsError {
		t.Error("unexpected error")
	}
}

func TestHandlers_StoreStats(t *testing.T) {
	h := newTestHandlers(t)
	result, _ := h.StoreStats(context.Background(), makeReq("store_stats", map[string]any{}))
	if result.IsError {
		t.Error("unexpected error")
	}
}

func TestHandlers_DBQuery_UnknownDB(t *testing.T) {
	h := newTestHandlers(t)
	result, _ := h.DBQuery(context.Background(), makeReq("db_query", map[string]any{"database": "NOPE", "query": "SELECT 1"}))
	if !result.IsError {
		t.Error("expected error for unknown database")
	}
}

func TestHandlers_DBQuery_Blocked(t *testing.T) {
	h := newTestHandlers(t)
	result, _ := h.DBQuery(context.Background(), makeReq("db_query", map[string]any{"database": "X", "query": "DROP TABLE x"}))
	if !result.IsError {
		t.Error("expected error for blocked query")
	}
}

func TestHandlers_DBListTables_UnknownDB(t *testing.T) {
	h := newTestHandlers(t)
	result, _ := h.DBListTables(context.Background(), makeReq("db_list_tables", map[string]any{"database": "NOPE"}))
	if !result.IsError {
		t.Error("expected error")
	}
}

func TestHandlers_DBDescribe_UnknownDB(t *testing.T) {
	h := newTestHandlers(t)
	result, _ := h.DBDescribe(context.Background(), makeReq("db_describe", map[string]any{"database": "X", "table": "y"}))
	if !result.IsError {
		t.Error("expected error")
	}
}

func TestHandlers_MongoFind_Unknown(t *testing.T) {
	h := newTestHandlers(t)
	result, _ := h.MongoFind(context.Background(), makeReq("mongo_find", map[string]any{"database": "X", "collection": "y"}))
	if !result.IsError {
		t.Error("expected error")
	}
}

func TestHandlers_MongoFind_BlockedOperator(t *testing.T) {
	h := newTestHandlers(t)
	result, _ := h.MongoFind(context.Background(), makeReq("mongo_find", map[string]any{
		"database": "X", "collection": "y", "filter": map[string]any{"$where": "1==1"},
	}))
	if !result.IsError {
		t.Error("expected error for blocked operator")
	}
}

func TestHandlers_MongoListCollections_Unknown(t *testing.T) {
	h := newTestHandlers(t)
	result, _ := h.MongoListCollections(context.Background(), makeReq("mongo_list_collections", map[string]any{"database": "X"}))
	if !result.IsError {
		t.Error("expected error")
	}
}

func TestHandlers_RedisExec_Blocked(t *testing.T) {
	h := newTestHandlers(t)
	result, _ := h.RedisExec(context.Background(), makeReq("redis_exec", map[string]any{"database": "X", "command": "FLUSHALL"}))
	if !result.IsError {
		t.Error("expected error")
	}
}

func TestHandlers_RedisExec_Unknown(t *testing.T) {
	h := newTestHandlers(t)
	result, _ := h.RedisExec(context.Background(), makeReq("redis_exec", map[string]any{"database": "NOPE", "command": "GET"}))
	if !result.IsError {
		t.Error("expected error for unknown redis")
	}
}

func TestHandlers_RedisKeys_Unknown(t *testing.T) {
	h := newTestHandlers(t)
	result, _ := h.RedisKeys(context.Background(), makeReq("redis_keys", map[string]any{"database": "NOPE"}))
	if !result.IsError {
		t.Error("expected error")
	}
}

func TestHandlers_HTTPRequest_Unknown(t *testing.T) {
	h := newTestHandlers(t)
	result, _ := h.HTTPRequest(context.Background(), makeReq("http_request", map[string]any{"api": "NOPE", "path": "/x"}))
	if !result.IsError {
		t.Error("expected error")
	}
}

func TestHandlers_HTTPListAPIs(t *testing.T) {
	h := newTestHandlers(t)
	result, _ := h.HTTPListAPIs(context.Background(), makeReq("http_list_apis", map[string]any{}))
	if result.IsError {
		t.Error("unexpected error")
	}
}

func TestHandlers_AIChat_UnknownProvider(t *testing.T) {
	h := newTestHandlers(t)
	result, _ := h.AIChat(context.Background(), makeReq("ai_chat", map[string]any{
		"provider": "NOPE", "model": "x", "messages": []any{map[string]any{"role": "user", "content": "hi"}},
	}))
	if !result.IsError {
		t.Error("expected error")
	}
}

func TestHandlers_AIListProviders(t *testing.T) {
	h := newTestHandlers(t)
	result, _ := h.AIListProviders(context.Background(), makeReq("ai_list_providers", map[string]any{}))
	if result.IsError {
		t.Error("unexpected error")
	}
}

func TestHandlers_AIQuotaStatus(t *testing.T) {
	h := newTestHandlers(t)
	result, _ := h.AIQuotaStatus(context.Background(), makeReq("ai_quota_status", map[string]any{}))
	if result.IsError {
		t.Error("unexpected error")
	}
}

func TestHandlers_ConfigList(t *testing.T) {
	h := newTestHandlers(t)
	result, _ := h.ConfigList(context.Background(), makeReq("config_list", map[string]any{}))
	if result.IsError {
		t.Error("unexpected error")
	}
}

func TestHandlers_Version(t *testing.T) {
	h := newTestHandlers(t)
	result, _ := h.Version(context.Background(), makeReq("version", map[string]any{}))
	if result.IsError {
		t.Error("unexpected error")
	}
}

func TestHandlers_MissingRequiredParams(t *testing.T) {
	h := newTestHandlers(t)
	tests := []struct {
		name    string
		handler func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error)
		args    map[string]any
	}{
		{name: "scan no text", handler: h.ScanContext, args: map[string]any{}},
		{name: "redact no text", handler: h.RedactContext, args: map[string]any{}},
		{name: "unredact no text", handler: h.UnredactResponse, args: map[string]any{}},
		{name: "compress no text", handler: h.CompressContext, args: map[string]any{}},
		{name: "memory no text", handler: h.MemoryFilter, args: map[string]any{}},
		{name: "classify no text", handler: h.ClassifyData, args: map[string]any{}},
		{name: "db_query no database", handler: h.DBQuery, args: map[string]any{"query": "x"}},
		{name: "db_query no query", handler: h.DBQuery, args: map[string]any{"database": "x"}},
		{name: "db_list no db", handler: h.DBListTables, args: map[string]any{}},
		{name: "db_describe no db", handler: h.DBDescribe, args: map[string]any{"table": "x"}},
		{name: "mongo_find no db", handler: h.MongoFind, args: map[string]any{"collection": "x"}},
		{name: "mongo_find no col", handler: h.MongoFind, args: map[string]any{"database": "x"}},
		{name: "mongo_list no db", handler: h.MongoListCollections, args: map[string]any{}},
		{name: "redis no db", handler: h.RedisExec, args: map[string]any{"command": "x"}},
		{name: "redis no cmd", handler: h.RedisExec, args: map[string]any{"database": "x"}},
		{name: "redis_keys no db", handler: h.RedisKeys, args: map[string]any{}},
		{name: "http no api", handler: h.HTTPRequest, args: map[string]any{"path": "/x"}},
		{name: "http no path", handler: h.HTTPRequest, args: map[string]any{"api": "x"}},
		{name: "ai no provider", handler: h.AIChat, args: map[string]any{"model": "x", "messages": []any{}}},
		{name: "ai no model", handler: h.AIChat, args: map[string]any{"provider": "x", "messages": []any{}}},
		{name: "ai no messages", handler: h.AIChat, args: map[string]any{"provider": "x", "model": "x"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _ := tt.handler(context.Background(), makeReq("test", tt.args))
			if !result.IsError {
				t.Error("expected error for missing required param")
			}
		})
	}
}
