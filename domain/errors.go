package domain

import "errors"

// Sentinel errors for domain operations.
var (
	ErrDatabaseNotFound = errors.New("database not configured")
	ErrProviderNotFound = errors.New("AI provider not configured")
	ErrAPINotFound      = errors.New("API endpoint not configured")
	ErrBlockedQuery     = errors.New("query blocked by security policy")
	ErrDangerousCommand = errors.New("command blocked by security policy")
	ErrInjectionAttempt = errors.New("potential injection detected")
	ErrTextTooLarge     = errors.New("text exceeds maximum allowed size")
	ErrInvalidArgument  = errors.New("invalid argument")
	ErrConnectionFailed = errors.New("connection failed")
	ErrQueryFailed      = errors.New("query execution failed")
)

// SecurityError wraps a blocked operation with details.
type SecurityError struct {
	Op     string // operation attempted (DROP, FLUSHALL, $where, etc.)
	Reason string // why it was blocked
	Err    error  // underlying sentinel
}

func (e *SecurityError) Error() string {
	return e.Reason + ": " + e.Op
}

func (e *SecurityError) Unwrap() error {
	return e.Err
}

// NewBlockedQueryError creates a security error for blocked SQL.
func NewBlockedQueryError(op, reason string) *SecurityError {
	return &SecurityError{Op: op, Reason: reason, Err: ErrBlockedQuery}
}

// NewDangerousCommandError creates a security error for blocked commands.
func NewDangerousCommandError(op, reason string) *SecurityError {
	return &SecurityError{Op: op, Reason: reason, Err: ErrDangerousCommand}
}
