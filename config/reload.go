package config

import (
	"log"
	"os"
	"os/signal"
	"syscall"
)

// WatchReload listens for SIGHUP and reloads config.
// Calls the callback with the new config on each reload.
func WatchReload(callback func(*Config)) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)

	go func() {
		for range ch {
			log.Println("[CONFIG] SIGHUP received, reloading...")
			newCfg := Load()
			if err := newCfg.Validate(); err != nil {
				log.Printf("[CONFIG] Reload failed validation: %v", err)
				continue
			}
			callback(newCfg)
			log.Println("[CONFIG] Reload complete")
		}
	}()
}
