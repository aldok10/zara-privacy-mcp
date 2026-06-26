//go:build e2e

package e2e

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"
)

// jsonRPC sends a JSON-RPC 2.0 request and reads the response.
func jsonRPC(t *testing.T, stdin *bufio.Writer, stdout *bufio.Scanner, method string, id int, params any) map[string]any {
	t.Helper()

	req := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
	}
	if params != nil {
		req["params"] = params
	}

	data, _ := json.Marshal(req)
	data = append(data, '\n')
	stdin.Write(data)
	stdin.Flush()

	if !stdout.Scan() {
		t.Fatalf("no response for %s: %v", method, stdout.Err())
	}

	var resp map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON response for %s: %s", method, stdout.Text())
	}
	return resp
}

func TestE2E_StdioRoundtrip(t *testing.T) {
	// Build binary
	binary := t.TempDir() + "/zara-privacy-mcp"
	build := exec.Command("go", "build", "-o", binary, "./cmd/server/")
	build.Dir = ".."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %s\n%s", err, out)
	}

	// Start server
	cmd := exec.Command(binary)
	cmd.Env = append(os.Environ(),
		"ZARA_ENCRYPTION_KEY=e2e-test-key-32-bytes-minimum!!!",
		"ZARA_DB_PATH="+t.TempDir()+"/e2e.db",
	)

	stdinPipe, _ := cmd.StdinPipe()
	stdoutPipe, _ := cmd.StdoutPipe()
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start: %v", err)
	}
	defer func() {
		stdinPipe.Close()
		cmd.Wait()
	}()

	stdin := bufio.NewWriter(stdinPipe)
	stdout := bufio.NewScanner(stdoutPipe)

	// Give server time to initialize
	time.Sleep(500 * time.Millisecond)

	// 1. Initialize
	resp := jsonRPC(t, stdin, stdout, "initialize", 1, map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "e2e-test", "version": "1.0"},
	})
	if resp["error"] != nil {
		t.Fatalf("initialize error: %v", resp["error"])
	}
	result := resp["result"].(map[string]any)
	if result["serverInfo"] == nil {
		t.Fatal("no serverInfo in initialize response")
	}

	// 2. Send initialized notification
	notif, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	})
	stdin.Write(append(notif, '\n'))
	stdin.Flush()

	// 3. Call tools/list
	resp = jsonRPC(t, stdin, stdout, "tools/list", 2, nil)
	if resp["error"] != nil {
		t.Fatalf("tools/list error: %v", resp["error"])
	}
	toolsResult := resp["result"].(map[string]any)
	tools := toolsResult["tools"].([]any)
	if len(tools) < 20 {
		t.Errorf("expected 21 tools, got %d", len(tools))
	}

	// 4. Call scan_context
	resp = jsonRPC(t, stdin, stdout, "tools/call", 3, map[string]any{
		"name": "scan_context",
		"arguments": map[string]any{
			"text": "My API key is sk-proj-abc123def456ghi789jkl012mno345 and email is test@example.com",
		},
	})
	if resp["error"] != nil {
		t.Fatalf("scan_context error: %v", resp["error"])
	}
	callResult := resp["result"].(map[string]any)
	content := callResult["content"].([]any)
	if len(content) == 0 {
		t.Fatal("scan_context returned no content")
	}
	textContent := content[0].(map[string]any)["text"].(string)
	if textContent == "" {
		t.Fatal("empty scan result")
	}

	// Verify it detected something
	var scanResult map[string]any
	json.Unmarshal([]byte(textContent), &scanResult)
	riskScore := scanResult["risk_score"]
	if riskScore == nil || riskScore.(float64) == 0 {
		t.Error("expected non-zero risk score for text with API key + email")
	}

	// 5. Call version
	resp = jsonRPC(t, stdin, stdout, "tools/call", 4, map[string]any{
		"name":      "version",
		"arguments": map[string]any{},
	})
	if resp["error"] != nil {
		t.Fatalf("version error: %v", resp["error"])
	}

	fmt.Println("E2E: All stdio roundtrip tests passed")
}
