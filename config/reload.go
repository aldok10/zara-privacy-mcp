package config

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

// WatchReload listens for SIGHUP and reloads config. Stops when ctx is cancelled.
func WatchReload(ctx context.Context, logger *slog.Logger, callback func(*Config)) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)

	go func() {
		defer signal.Stop(ch)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ch:
				logger.Info("SIGHUP received, reloading config")
				newCfg := Load()
				if err := newCfg.Validate(); err != nil {
					logger.Warn("reload failed validation", "error", err)
					continue
				}
				callback(newCfg)
				logger.Info("config reload complete")
			}
		}
	}()
}
