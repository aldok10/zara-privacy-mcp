package bootstrap

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	mcpserver "github.com/mark3labs/mcp-go/server"
	"go.uber.org/fx"

	"github.com/aldok10/zara-privacy-mcp/config"
	"github.com/aldok10/zara-privacy-mcp/internal/db"
	"github.com/aldok10/zara-privacy-mcp/internal/store"
	"github.com/aldok10/zara-privacy-mcp/transport"
)

// Params for bootstrap invocation.
type Params struct {
	fx.In

	Lifecycle     fx.Lifecycle
	Shutdowner    fx.Shutdowner
	Logger        *slog.Logger
	Config        *config.Config
	Server        *transport.MCPServer
	Store         *store.MappingStore
	DBRegistry    *db.Registry
	MongoRegistry *db.MongoRegistry
	RedisRegistry *db.RedisRegistry
	Detectors     detectors
}

// Invoke wires lifecycle hooks.
func Invoke(p Params) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// Context for background goroutines (cancelled on shutdown)
	ctx, cancel := context.WithCancel(context.Background())

	// Hot-reload config on SIGHUP — reconnect services
	config.WatchReload(ctx, logger, func(newCfg *config.Config) {
		logger.Info("config reloaded, reconnecting services")

		// Reconnect SQL databases
		p.DBRegistry.CloseAll()
		for _, dbc := range newCfg.Databases {
			if err := p.DBRegistry.Add(db.Config{
				Name: dbc.Name, Driver: dbc.Driver, DSN: dbc.DSN,
				MaxConns: dbc.MaxConns, MaxIdleConns: dbc.MaxIdleConns,
			}, p.Detectors.Secret, p.Detectors.PII); err != nil {
				logger.Warn("reload: failed to reconnect DB", "name", dbc.Name, "error", err)
			}
		}

		// Reconnect Redis
		p.RedisRegistry.CloseAll()
		for _, rc := range newCfg.RedisDBs {
			if err := p.RedisRegistry.Add(db.RedisConfig{
				Name: rc.Name, Addr: rc.Addr, Username: rc.Username,
				Password: rc.Password, DB: rc.DB, TLS: rc.TLS,
			}, p.Detectors.Secret, p.Detectors.PII); err != nil {
				logger.Warn("reload: failed to reconnect Redis", "name", rc.Name, "error", err)
			}
		}

		// Reconnect MongoDB
		p.MongoRegistry.CloseAll()
		for _, mc := range newCfg.MongoDBs {
			if err := p.MongoRegistry.Add(db.MongoConfig{
				Name: mc.Name, URI: mc.URI, Database: mc.Database,
			}, p.Detectors.Secret, p.Detectors.PII); err != nil {
				logger.Warn("reload: failed to reconnect MongoDB", "name", mc.Name, "error", err)
			}
		}

		logger.Info("services reconnected")
	})

	p.Lifecycle.Append(fx.Hook{
		OnStart: func(_ context.Context) error {
			logger.Info("Zara Privacy MCP starting", "tools", 22, "transport", p.Config.Transport)

			switch p.Config.Transport {
			case "http", "streamable-http":
				go startHTTPTransport(p, logger)
			default:
				go startStdioTransport(p, logger)
			}
			return nil
		},
		OnStop: func(_ context.Context) error {
			logger.Info("shutting down...")
			cancel() // stop background goroutines
			p.Store.Close()
			p.DBRegistry.CloseAll()
			p.MongoRegistry.CloseAll()
			p.RedisRegistry.CloseAll()
			return nil
		},
	})
}

func startStdioTransport(p Params, logger *slog.Logger) {
	if err := mcpserver.ServeStdio(p.Server.Server()); err != nil {
		logger.Info("stdio server stopped", "reason", err.Error())
	}
	p.Shutdowner.Shutdown()
}

func startHTTPTransport(p Params, logger *slog.Logger) {
	addr := fmt.Sprintf("%s:%s", p.Config.Host, p.Config.Port)

	httpServer := mcpserver.NewStreamableHTTPServer(p.Server.Server())

	mux := http.NewServeMux()
	mux.Handle("/mcp", httpServer)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ready"}`))
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	logger.Info("HTTP transport listening", "addr", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("HTTP server error", "error", err)
	}
	p.Shutdowner.Shutdown()
}

func expandHome(path string) string {
	if len(path) > 0 && path[0] == '~' {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			// Fallback to temp dir if HOME unavailable (containers)
			home = os.TempDir()
		}
		return filepath.Join(home, path[1:])
	}
	return path
}
