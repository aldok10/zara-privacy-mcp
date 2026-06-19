package config

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

// WatchReload listens for SIGHUP and reloads config.
func WatchReload(logger *slog.Logger, callback func(*Config)) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)

	go func() {
		for range ch {
			logger.Info("SIGHUP received, reloading config")
			newCfg := Load()
			if err := newCfg.Validate(); err != nil {
				logger.Warn("reload failed validation", "error", err)
				continue
			}
			callback(newCfg)
			logger.Info("config reload complete")
		}
	}()
}
