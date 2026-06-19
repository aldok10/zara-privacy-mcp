package ai

// ScanDirection indicates whether scanning input or output.
type ScanDirection int

const (
	ScanInput  ScanDirection = iota // Before sending to provider
	ScanOutput                      // After receiving from provider
)

// GatewayPolicy defines what the AI gateway enforces.
type GatewayPolicy struct {
	// RedactInput: if true, redact secrets/PII from messages before sending.
	RedactInput bool
	// ScanOutput: if true, scan provider response for leaked PII.
	ScanOutput bool
	// BlockOnLeak: if true, block response if output contains PII that wasn't in input.
	BlockOnLeak bool
	// MaxInputSize: maximum total message content size (bytes).
	MaxInputSize int
}

// DefaultPolicy returns a secure-by-default policy.
func DefaultPolicy() GatewayPolicy {
	return GatewayPolicy{
		RedactInput:  true,
		ScanOutput:   true,
		BlockOnLeak:  false, // log only by default, don't break flow
		MaxInputSize: 512 * 1024, // 512KB
	}
}

// GatewayEvent is emitted by the AI gateway for observability.
type GatewayEvent struct {
	Direction     ScanDirection
	Provider      string
	Model         string
	RedactedCount int    // how many fields were redacted in input
	LeakedCount   int    // how many PII found in output (not from input)
	Blocked       bool   // whether the response was blocked
	Duration      string
}

// InputSanitizer prepares messages for sending to AI providers.
// Strategy pattern: different sanitizers can be swapped.
type InputSanitizer interface {
	// Sanitize processes messages before they are sent to the provider.
	// Returns sanitized messages and the count of redacted fields.
	Sanitize(messages []ChatMessage) ([]ChatMessage, int)
}

// OutputScanner checks AI provider responses for leaked sensitive data.
type OutputScanner interface {
	// Scan checks the response content for sensitive data.
	// Returns findings (leaked PII/secrets found in output).
	Scan(content string) []OutputFinding
}

// OutputFinding represents sensitive data found in AI output.
type OutputFinding struct {
	Type       string `json:"type"`
	Value      string `json:"value"`
	Risk       int    `json:"risk"`
	WasInInput bool   `json:"was_in_input"` // true = expected (was redacted from input), false = leaked by model
}
