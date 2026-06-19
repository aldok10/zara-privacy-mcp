// Package audit provides file-based logging of blocked/security operations.
package audit

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// Logger writes blocked operations to a file.
type Logger struct {
	mu   sync.Mutex
	file *os.File
}

// New creates an audit logger. Returns nil if path is empty.
func New(path string) *Logger {
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil
	}
	return &Logger{file: f}
}

// LogBlocked records a blocked operation.
func (l *Logger) LogBlocked(tool, reason string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.file, "%s BLOCKED tool=%s reason=%s\n",
		time.Now().UTC().Format(time.RFC3339), tool, reason)
}

// Close closes the audit log file.
func (l *Logger) Close() {
	if l == nil || l.file == nil {
		return
	}
	l.file.Close()
}
