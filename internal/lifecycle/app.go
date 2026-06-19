// Package lifecycle provides a minimal application lifecycle manager.
// Inspired by uber-go/fx and runfx — manages ordered startup, graceful
// shutdown, and service registration without reflection or heavy DI.
package lifecycle

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// Service is anything that can be started and stopped.
type Service interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}

// Hook is a pair of start/stop functions for lightweight lifecycle participants.
type Hook struct {
	OnStart func(ctx context.Context) error
	OnStop  func(ctx context.Context) error
}

// App manages the application lifecycle.
type App struct {
	name     string
	services []namedService
	hooks    []Hook
	mu       sync.Mutex
	running  bool
}

type namedService struct {
	name    string
	service Service
}

// New creates a new App with the given name.
func New(name string) *App {
	return &App{name: name}
}

// Register adds a named service to the lifecycle.
// Services are started in registration order and stopped in reverse.
func (a *App) Register(name string, svc Service) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.services = append(a.services, namedService{name: name, service: svc})
}

// Append adds a hook (start/stop pair) to the lifecycle.
func (a *App) Append(h Hook) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.hooks = append(a.hooks, h)
}

// Run starts all services, waits for interrupt, then stops in reverse order.
func (a *App) Run(ctx context.Context) error {
	a.mu.Lock()
	a.running = true
	a.mu.Unlock()

	log.Printf("[%s] starting (%d services, %d hooks)", a.name, len(a.services), len(a.hooks))

	// Start hooks
	for i, h := range a.hooks {
		if h.OnStart != nil {
			if err := h.OnStart(ctx); err != nil {
				a.stopPartial(ctx, i-1)
				return fmt.Errorf("hook %d start: %w", i, err)
			}
		}
	}

	// Start services in order
	for i, ns := range a.services {
		log.Printf("[%s] starting service: %s", a.name, ns.name)
		if err := ns.service.Start(ctx); err != nil {
			a.stopServices(ctx, i-1)
			return fmt.Errorf("service %s start: %w", ns.name, err)
		}
	}

	log.Printf("[%s] all services started", a.name)

	// Wait for interrupt
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		log.Printf("[%s] received %v, shutting down...", a.name, sig)
	case <-ctx.Done():
		log.Printf("[%s] context cancelled, shutting down...", a.name)
	}

	return a.Shutdown(ctx)
}

// Shutdown stops all services and hooks in reverse order.
func (a *App) Shutdown(ctx context.Context) error {
	a.mu.Lock()
	a.running = false
	a.mu.Unlock()

	var firstErr error

	// Stop services in reverse
	for i := len(a.services) - 1; i >= 0; i-- {
		ns := a.services[i]
		log.Printf("[%s] stopping service: %s", a.name, ns.name)
		if err := ns.service.Stop(ctx); err != nil {
			log.Printf("[%s] error stopping %s: %v", a.name, ns.name, err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}

	// Stop hooks in reverse
	for i := len(a.hooks) - 1; i >= 0; i-- {
		if a.hooks[i].OnStop != nil {
			if err := a.hooks[i].OnStop(ctx); err != nil {
				if firstErr == nil {
					firstErr = err
				}
			}
		}
	}

	log.Printf("[%s] shutdown complete", a.name)
	return firstErr
}

func (a *App) stopServices(ctx context.Context, upTo int) {
	for i := upTo; i >= 0; i-- {
		a.services[i].service.Stop(ctx)
	}
}

func (a *App) stopPartial(ctx context.Context, upTo int) {
	for i := upTo; i >= 0; i-- {
		if a.hooks[i].OnStop != nil {
			a.hooks[i].OnStop(ctx)
		}
	}
}
