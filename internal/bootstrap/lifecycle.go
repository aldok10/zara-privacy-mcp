package bootstrap

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"

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
	Server        *transport.MCPServer
	Store         *store.MappingStore
	DBRegistry    *db.Registry
	MongoRegistry *db.MongoRegistry
	RedisRegistry *db.RedisRegistry
}

// Invoke wires lifecycle hooks.
func Invoke(p Params) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// Context for background goroutines (cancelled on shutdown)
	ctx, cancel := context.WithCancel(context.Background())

	// Hot-reload config on SIGHUP
	config.WatchReload(ctx, logger, func(newCfg *config.Config) {
		logger.Info("config reloaded")
	})

	p.Lifecycle.Append(fx.Hook{
		OnStart: func(_ context.Context) error {
			logger.Info("Zara Privacy MCP starting", "tools", 21)
			go func() {
				if err := mcpserver.ServeStdio(p.Server.Server()); err != nil {
					logger.Info("server stopped", "reason", err.Error())
				}
				// Stdio ended (EOF) — trigger app shutdown
				p.Shutdowner.Shutdown()
			}()
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
