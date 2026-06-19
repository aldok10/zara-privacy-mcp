package transport_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/aldok10/zara-privacy-mcp/application/tools"
	"github.com/aldok10/zara-privacy-mcp/internal/classify"
	"github.com/aldok10/zara-privacy-mcp/internal/compress"
	"github.com/aldok10/zara-privacy-mcp/internal/detector"
	"github.com/aldok10/zara-privacy-mcp/internal/engine"
	"github.com/aldok10/zara-privacy-mcp/internal/store"
	"github.com/aldok10/zara-privacy-mcp/transport"
)

func setupTestServer(t *testing.T) *server.MCPServer {
	t.Helper()
	ms, err := store.NewMappingStore(t.TempDir()+"/test.db", []byte("test-key-32-bytes-long-minimum!!"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ms.Close() })

	sd := detector.NewSecretDetector()
	pd := detector.NewPIIDetector()

	h := &tools.Handlers{
		Engine:         engine.NewRedactEngine(sd, pd, ms),
		Compressor:     compress.NewCompressor(4096),
		Classifier:     classify.NewClassifier(),
		Store:          ms,
		DefaultLocales: []string{"id", "sg", "global"},
	}

	return transport.NewMCPServer(h, nil).Server()
}

func TestToolsRegistered(t *testing.T) {
	s := setupTestServer(t)
	// Verify the server was created (non-nil)
	if s == nil {
		t.Fatal("expected non-nil server")
	}
}

func TestScanContext(t *testing.T) {
	s := setupTestServer(t)

	req := mcp.CallToolRequest{}
	req.Params.Name = "scan_context"
	req.Params.Arguments = map[string]any{
		"text": "my email is test@example.com",
	}

	result, err := callTool(s, req)
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("unexpected error: %v", result.Content)
	}

	text := result.Content[0].(mcp.TextContent).Text
	var scan struct {
		RiskScore int `json:"risk_score"`
		PIIFound  []struct {
			Type string `json:"type"`
		} `json:"pii_found"`
	}
	if err := json.Unmarshal([]byte(text), &scan); err != nil {
		t.Fatal(err)
	}
	if scan.RiskScore == 0 {
		t.Error("expected non-zero risk score")
	}
	if len(scan.PIIFound) == 0 {
		t.Error("expected PII findings")
	}
}

func TestSecurityBlocksDropTable(t *testing.T) {
	s := setupTestServer(t)

	req := mcp.CallToolRequest{}
	req.Params.Name = "db_query"
	req.Params.Arguments = map[string]any{
		"database": "test",
		"query":    "DROP TABLE users",
	}

	result, err := callTool(s, req)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatal("expected error for DROP TABLE")
	}
	text := result.Content[0].(mcp.TextContent).Text
	if text == "" {
		t.Error("expected error message")
	}
}

func TestSecurityBlocksFlushAll(t *testing.T) {
	s := setupTestServer(t)

	req := mcp.CallToolRequest{}
	req.Params.Name = "redis_exec"
	req.Params.Arguments = map[string]any{
		"database": "test",
		"command":  "FLUSHALL",
	}

	result, err := callTool(s, req)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatal("expected error for FLUSHALL")
	}
}

// callTool invokes a tool handler directly via the server's internal dispatch.
func callTool(s *server.MCPServer, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ctx := context.Background()
	// Use the server's HandleMessage to simulate a tool call
	jsonReq := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      req.Params.Name,
			"arguments": req.Params.Arguments,
		},
	}
	reqBytes, _ := json.Marshal(jsonReq)

	respBytes := s.HandleMessage(ctx, reqBytes)

	// HandleMessage returns mcp.JSONRPCMessage; marshal it back to bytes
	respJSON, _ := json.Marshal(respBytes)

	var resp struct {
		Result struct {
			Content []json.RawMessage `json:"content"`
			IsError bool              `json:"isError"`
		} `json:"result"`
	}
	if err := json.Unmarshal(respJSON, &resp); err != nil {
		return nil, err
	}

	result := &mcp.CallToolResult{IsError: resp.Result.IsError}
	for _, raw := range resp.Result.Content {
		var c struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}
		json.Unmarshal(raw, &c)
		if c.Type == "text" {
			result.Content = append(result.Content, mcp.TextContent{Type: "text", Text: c.Text})
		}
	}
	return result, nil
}
