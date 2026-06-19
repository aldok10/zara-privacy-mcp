// Zara Privacy MCP — Context security layer for OpenCode.
//
// Zara Privacy MCP is a sidecar process that sits between OpenCode and LLM providers.
// It automatically detects, redacts, and restores sensitive data (secrets, PII) so
// that private information never leaves your machine unredacted.
//
// Architecture:
//
//	OpenCode ←→ Zara Privacy MCP (sidecar) ←→ LLM Provider
//	              ↓
//	         SQLite (encrypted mapping store)
//
// Tools:
//   - scan_context:      Detect secrets and PII without modifying text
//   - redact_context:    Replace sensitive data with reversible placeholders
//   - unredact_response: Restore original values in LLM responses
//   - compress_context:  Reduce token usage via dedup and extraction
//   - memory_filter:     Validate memory before persistence
//   - classify_data:     Classify data by sensitivity level
//   - store_stats:       Get mapping store statistics
package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/aldok10/zara-privacy-mcp/config"
	"github.com/aldok10/zara-privacy-mcp/internal/detector"
	"github.com/aldok10/zara-privacy-mcp/internal/mcp"
	"github.com/aldok10/zara-privacy-mcp/internal/store"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	log.Println("[Zara Privacy MCP] Starting...")

	// Load configuration
	cfg := config.Load()

	// Validate encryption key
	if cfg.EncryptionKey == "" {
		log.Println("[WARN] ZARA_ENCRYPTION_KEY not set. Using insecure default key.")
		log.Println("[WARN] Set a strong passphrase via env var for production use.")
		cfg.EncryptionKey = "zara-privacy-mcp-default-key-change-me!"
	}

	if len(cfg.EncryptionKey) < 16 {
		log.Fatalf("[FATAL] Encryption key must be at least 16 characters (got %d)", len(cfg.EncryptionKey))
	}

	// Expand ~ in DB path
	dbPath := expandHome(cfg.DBPath)
	dbDir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dbDir, 0700); err != nil {
		log.Fatalf("[FATAL] Cannot create DB directory %s: %v", dbDir, err)
	}
	log.Printf("[INFO] Using database: %s", dbPath)

	// Initialize components
	secretDetector := detector.NewSecretDetector()
	piiDetector := detector.NewPIIDetector()

	mappingStore, err := store.NewMappingStore(dbPath, []byte(cfg.EncryptionKey))
	if err != nil {
		log.Fatalf("[FATAL] Failed to initialize mapping store: %v", err)
	}
	defer mappingStore.Close()

	// Create MCP server
	mcpCfg := &mcp.Config{
		Port:           cfg.Port,
		Host:           cfg.Host,
		ServerName:     cfg.ServerName,
		ServerVersion:  cfg.ServerVersion,
		DefaultLocales: cfg.DefaultLocales,
		MaxTokens:      cfg.MaxTokens,
	}

	server := mcp.NewServer(mcpCfg, secretDetector, piiDetector, mappingStore)

	// Start metrics server if enabled
	if cfg.MetricsEnable {
		go func() {
			metricsAddr := fmt.Sprintf("%s:%s", cfg.Host, cfg.MetricsPort)
			log.Printf("[INFO] Starting metrics server on %s", metricsAddr)
			// Simple health endpoint on metrics port
			// Phase 2: add proper Prometheus /metrics
		}()
	}

	// Handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("[INFO] Received signal %v, shutting down...", sig)
		server.Stop()
		os.Exit(0)
	}()

	// Print startup banner
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════╗")
	fmt.Println("║        Zara Privacy MCP v0.1.0           ║")
	fmt.Println("║                                          ║")
	fmt.Printf("║  Listening:  %s:%s                    ║\n", cfg.Host, cfg.Port)
	fmt.Printf("║  Endpoint:   /mcp                         ║")
	fmt.Println()
	fmt.Println("║  Tools:                                  ║")
	fmt.Println("║    • scan_context      (detect secrets)  ║")
	fmt.Println("║    • redact_context    (replace secrets) ║")
	fmt.Println("║    • unredact_response (restore secrets) ║")
	fmt.Println("║    • compress_context  (save tokens)     ║")
	fmt.Println("║    • memory_filter     (protect memory)  ║")
	fmt.Println("║    • classify_data     (sensitivity)     ║")
	fmt.Println("║    • store_stats       (mapping stats)   ║")
	fmt.Println("╚══════════════════════════════════════════╝")
	fmt.Println()

	// Start MCP server
	if err := server.Start(); err != nil {
		log.Fatalf("[FATAL] Server error: %v", err)
	}
}

// expandHome replaces ~ with the home directory.
func expandHome(path string) string {
	if len(path) > 0 && path[0] == '~' {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return filepath.Join(home, path[1:])
	}
	return path
}
