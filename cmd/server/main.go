// Zara Secure MCP — General-purpose secure gateway for OpenCode.
//
// Zara Secure MCP is a sidecar process that provides privacy layer,
// database proxy, HTTP API proxy, and AI provider proxy — all with
// automatic data masking.
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
	"flag"
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

// stdioMode is set via --stdio flag for OpenCode sidecar spawning.
var stdioMode = flag.Bool("stdio", false, "Run in stdio mode (for OpenCode MCP spawn)")

func main() {
	flag.Parse()
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	// Load configuration (flag overrides env)
	cfg := config.Load()
	if *stdioMode {
		cfg.Transport = "stdio"
	}

	log.Printf("[Zara Privacy MCP] Starting... (transport=%s)", cfg.Transport)

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

	server := mcp.NewServer(mcpCfg, cfg, secretDetector, piiDetector, mappingStore)

	// Hot-reload: SIGHUP reloads configuration
	if cfg.ReloadSignal {
		config.NewReloader(cfg, func(newCfg *config.Config) {
			log.Println("[INFO] Config reloaded. New connections will use updated settings.")
		})
	}

	// Transport decision
	switch cfg.Transport {
	case "stdio":
		// Stdio mode: OpenCode spawns us and communicates over stdin/stdout
		// No startup banner (binary protocol), just serve
		if err := server.StartStdio(); err != nil {
			log.Fatalf("[FATAL] Stdio server error: %v", err)
		}

	case "http":
		// HTTP mode: standalone server for development, Postman testing
		go func() {
			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
			sig := <-sigCh
			log.Printf("[INFO] Received signal %v, shutting down...", sig)
			server.Stop()
			os.Exit(0)
		}()

		// Print startup banner
		fmt.Println()
		fmt.Println("╔══════════════════════════════════════════════╗")
		fmt.Println("║          Zara Secure MCP v0.2.0             ║")
		fmt.Println("║                                              ║")
		fmt.Printf("║  Listening:  %s:%s                        ║\n", cfg.Host, cfg.Port)
		fmt.Printf("║  Endpoint:   http://%s:%s/mcp               ║\n", cfg.Host, cfg.Port)
		fmt.Println("║                                              ║")
		fmt.Println("║  15 tools available via MCP protocol:       ║")
		fmt.Println("║  ── Privacy ──                               ║")
		fmt.Println("║    • scan_context      (detect secrets)      ║")
		fmt.Println("║    • redact_context    (replace secrets)     ║")
		fmt.Println("║    • unredact_response (restore secrets)     ║")
		fmt.Println("║    • compress_context  (save tokens)         ║")
		fmt.Println("║    • memory_filter     (protect memory)      ║")
		fmt.Println("║    • classify_data     (sensitivity)         ║")
		fmt.Println("║    • store_stats       (mapping stats)       ║")
		fmt.Println("║  ── Database ──                               ║")
		fmt.Println("║    • db_query          (SQL + auto-mask)     ║")
		fmt.Println("║    • db_list_tables    (schema discovery)    ║")
		fmt.Println("║    • db_describe       (column details)      ║")
		fmt.Println("║  ── HTTP API ──                               ║")
		fmt.Println("║    • http_request      (curl + auto-mask)    ║")
		fmt.Println("║    • http_list_apis    (list endpoints)      ║")
		fmt.Println("║  ── AI Provider ──                            ║")
		fmt.Println("║    • ai_chat           (LLM + auto-redact)   ║")
		fmt.Println("║    • ai_list_providers (list providers)      ║")
		fmt.Println("║  ── Config ──                                 ║")
		fmt.Println("║    • config_list       (show connections)    ║")
		fmt.Println("╚══════════════════════════════════════════════╝")
		fmt.Println()

		if err := server.Start(); err != nil {
			log.Fatalf("[FATAL] HTTP server error: %v", err)
		}

	default:
		log.Fatalf("[FATAL] Unknown transport: %s (use 'http' or 'stdio')", cfg.Transport)
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
