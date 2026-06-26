// Zara Privacy MCP — Privacy-first MCP gateway for AI agents.
package main

import (
	"log/slog"
	"os"

	"gitlab.com/minifx/runfx"
	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"

	"github.com/aldok10/zara-privacy-mcp/internal/bootstrap"
)

func main() {
	// MCP stdio requires stdout for JSON-RPC only — all logs must go to stderr
	stderrLogger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	app, err := runfx.NewApp(
		&bootstrap.ConfigLoader{},
		fx.WithLogger(func() fxevent.Logger {
			return &fxevent.SlogLogger{Logger: stderrLogger}
		}),
		bootstrap.Module,
		fx.Invoke(bootstrap.Invoke),
	)
	if err != nil {
		stderrLogger.Error("failed to create app", "error", err)
		os.Exit(1)
	}

	app.Run()
}
