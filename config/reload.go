// Package config provides configuration loading with hot-reload support.
package config

import (
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// Reloader handles hot-reloading of configuration via SIGHUP.
type Reloader struct {
	mu        sync.RWMutex
	cfg       *Config
	reloadFn  func(*Config)
	sigCh     chan os.Signal
}

// NewReloader creates a reloader that watches for SIGHUP.
// When SIGHUP is received, it re-reads env vars and calls reloadFn with the new config.
func NewReloader(initial *Config, reloadFn func(*Config)) *Reloader {
	r := &Reloader{
		cfg:      initial,
		reloadFn: reloadFn,
		sigCh:    make(chan os.Signal, 1),
	}

	signal.Notify(r.sigCh, syscall.SIGHUP)

	go r.watch()

	return r
}

// Get returns the current config (thread-safe).
func (r *Reloader) Get() *Config {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cfg
}

// ReloadNow forces an immediate config reload.
func (r *Reloader) ReloadNow() {
	r.doReload()
}

func (r *Reloader) watch() {
	for range r.sigCh {
		log.Println("[Config] SIGHUP received — reloading configuration...")
		r.doReload()
	}
}

func (r *Reloader) doReload() {
	newCfg := Load()

	r.mu.Lock()
	r.cfg = newCfg
	r.mu.Unlock()

	if r.reloadFn != nil {
		r.reloadFn(newCfg)
	}

	log.Println("[Config] Configuration reloaded successfully")
}

// Stop gracefully stops the reload watcher.
func (r *Reloader) Stop() {
	signal.Stop(r.sigCh)
	close(r.sigCh)
}
