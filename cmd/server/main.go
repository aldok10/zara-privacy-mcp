// Zara Privacy MCP — Privacy-first MCP gateway for AI agents.
//
// 19 tools: privacy layer + database proxy (SQL/MongoDB/Redis) +
// HTTP API proxy + AI provider proxy — all with automatic data masking.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"path/filepath"
	"time"

	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/aldok10/zara-privacy-mcp/application/tools"
	"github.com/aldok10/zara-privacy-mcp/config"
	"github.com/aldok10/zara-privacy-mcp/internal/ai"
	"github.com/aldok10/zara-privacy-mcp/internal/classify"
	"github.com/aldok10/zara-privacy-mcp/internal/compress"
	"github.com/aldok10/zara-privacy-mcp/internal/db"
	"github.com/aldok10/zara-privacy-mcp/internal/detector"
	"github.com/aldok10/zara-privacy-mcp/internal/engine"
	httpproxy "github.com/aldok10/zara-privacy-mcp/internal/http"
	"github.com/aldok10/zara-privacy-mcp/internal/lifecycle"
	"github.com/aldok10/zara-privacy-mcp/internal/observe"
	"github.com/aldok10/zara-privacy-mcp/internal/store"
	"github.com/aldok10/zara-privacy-mcp/transport"
)

var stdioMode = flag.Bool("stdio", false, "Run in stdio mode (for MCP clients)")

func main() {
	flag.Parse()
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	cfg := config.Load()
	if *stdioMode {
		cfg.Transport = "stdio"
	}
	if err := cfg.Validate(); err != nil {
		log.Fatalf("[FATAL] Invalid config: %v", err)
	}

	// Validate encryption key
	if cfg.EncryptionKey == "" {
		log.Println("[WARN] ZARA_ENCRYPTION_KEY not set. Using insecure default key.")
		cfg.EncryptionKey = "zara-privacy-mcp-default-key-change-me!"
	}
	if len(cfg.EncryptionKey) < 16 {
		log.Fatalf("[FATAL] Encryption key must be at least 16 characters (got %d)", len(cfg.EncryptionKey))
	}

	// Initialize mapping store
	dbPath := expandHome(cfg.DBPath)
	if err := os.MkdirAll(filepath.Dir(dbPath), 0700); err != nil {
		log.Fatalf("[FATAL] Cannot create DB directory: %v", err)
	}
	mappingStore, err := store.NewMappingStore(dbPath, []byte(cfg.EncryptionKey))
	if err != nil {
		log.Fatalf("[FATAL] Failed to initialize mapping store: %v", err)
	}

	// Initialize detectors
	secretDet := detector.NewSecretDetector()
	piiDet := detector.NewPIIDetector()

	// Initialize registries
	dbRegistry := db.NewRegistry()
	mongoRegistry := db.NewMongoRegistry()
	redisRegistry := db.NewRedisRegistry()
	apiRegistry := httpproxy.NewRegistry(secretDet, piiDet)
	aiRegistry := ai.NewRegistry()

	// Register configured connections
	registerDatabases(cfg, dbRegistry, secretDet, piiDet)
	registerMongos(cfg, mongoRegistry, secretDet, piiDet)
	registerRedis(cfg, redisRegistry, secretDet, piiDet)
	registerAPIs(cfg, apiRegistry)
	registerAIProviders(cfg, aiRegistry)

	// Build tool handlers
	handlers := &tools.Handlers{
		Engine:         engine.NewRedactEngine(secretDet, piiDet, mappingStore),
		Compressor:     compress.NewCompressor(cfg.MaxTokens),
		Classifier:     classify.NewClassifier(),
		Store:          mappingStore,
		DBRegistry:     dbRegistry,
		MongoRegistry:  mongoRegistry,
		RedisRegistry:  redisRegistry,
		APIRegistry:    apiRegistry,
		AIRegistry:     aiRegistry,
		AppConfig:      cfg,
		DefaultLocales: cfg.DefaultLocales,
	}

	// OpenObserve telemetry (nil-safe — disabled if URL empty)
	obs := observe.New(observe.Config{
		URL:    cfg.ObserveURL,
		User:   cfg.ObserveUser,
		Key:    cfg.ObserveKey,
		Stream: cfg.ObserveStream,
	})

	// Create MCP server
	s := transport.NewMCPServer(handlers, obs)

	// Application lifecycle — ordered startup, graceful shutdown
	app := lifecycle.New("zara-privacy-mcp")
	app.Append(lifecycle.Hook{
		OnStop: func(ctx context.Context) error {
			mappingStore.Close()
			dbRegistry.CloseAll()
			mongoRegistry.CloseAll()
			redisRegistry.CloseAll()
			return nil
		},
	})

	// For stdio mode: serve synchronously (no signal wait needed — mcp-go handles EOF)
	log.Printf("[Zara Privacy MCP] Starting... (transport=%s)", cfg.Transport)
	if err := mcpserver.ServeStdio(s); err != nil {
		log.Printf("[INFO] Server stopped: %v", err)
	}

	// Graceful shutdown
	app.Shutdown(context.Background())
}

// ─── Registration helpers ───────────────────────────────────────────────────

func registerDatabases(cfg *config.Config, reg *db.Registry, sd *detector.SecretDetector, pd *detector.PIIDetector) {
	for _, dbc := range cfg.Databases {
		if err := reg.Add(db.Config{
			Name: dbc.Name, Driver: dbc.Driver, DSN: dbc.DSN,
			MaxConns: dbc.MaxConns, MaxIdleConns: dbc.MaxIdleConns,
			ConnMaxLifetime: time.Duration(dbc.ConnMaxLifetime) * time.Second,
			ConnMaxIdleTime: time.Duration(dbc.ConnMaxIdleTime) * time.Second,
		}, sd, pd); err != nil {
			log.Printf("[WARN] DB %s: %v", dbc.Name, err)
		} else {
			log.Printf("[INFO] DB connected: %s (%s)", dbc.Name, dbc.Driver)
		}
	}
}

func registerMongos(cfg *config.Config, reg *db.MongoRegistry, sd *detector.SecretDetector, pd *detector.PIIDetector) {
	for _, mc := range cfg.MongoDBs {
		if err := reg.Add(db.MongoConfig{
			Name: mc.Name, URI: mc.URI, Database: mc.Database,
		}, sd, pd); err != nil {
			log.Printf("[WARN] MongoDB %s: %v", mc.Name, err)
		} else {
			log.Printf("[INFO] MongoDB connected: %s/%s", mc.Name, mc.Database)
		}
	}
}

func registerRedis(cfg *config.Config, reg *db.RedisRegistry, sd *detector.SecretDetector, pd *detector.PIIDetector) {
	for _, rc := range cfg.RedisDBs {
		if err := reg.Add(db.RedisConfig{
			Name: rc.Name, Addr: rc.Addr, Username: rc.Username,
			Password: rc.Password, DB: rc.DB, PoolSize: rc.PoolSize,
			MinIdleConns: rc.MinIdleConns,
			ConnMaxIdleTime: time.Duration(rc.ConnMaxIdleTime) * time.Second,
		}, sd, pd); err != nil {
			log.Printf("[WARN] Redis %s: %v", rc.Name, err)
		} else {
			log.Printf("[INFO] Redis connected: %s → %s", rc.Name, rc.Addr)
		}
	}
}

func registerAPIs(cfg *config.Config, reg *httpproxy.Registry) {
	for _, apic := range cfg.APIs {
		reg.Add(httpproxy.APIConfig{
			Name: apic.Name, BaseURL: apic.BaseURL,
			AuthType: apic.AuthType, AuthEnv: apic.AuthEnv, Headers: apic.Headers,
		})
		log.Printf("[INFO] API registered: %s → %s", apic.Name, apic.BaseURL)
	}
}

func registerAIProviders(cfg *config.Config, reg *ai.Registry) {
	for _, aic := range cfg.AIProviders {
		reg.Add(ai.Provider{
			Name: aic.Name, BaseURL: aic.BaseURL,
			APIKey: aic.APIKey, Models: aic.Models,
		})
		log.Printf("[INFO] AI provider: %s (%d models)", aic.Name, len(aic.Models))
	}
}

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
