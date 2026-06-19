// Package detector defines core types for secret and PII detection.
package detector

// Classification levels for data sensitivity.
type Classification string

const (
	Public       Classification = "PUBLIC"
	Internal     Classification = "INTERNAL"
	Confidential Classification = "CONFIDENTIAL"
	Secret       Classification = "SECRET"
)

// Risk represents a risk assessment score.
type Risk int

const (
	RiskNone  Risk = 0
	RiskLow   Risk = 1
	RiskMid   Risk = 2
	RiskHigh  Risk = 3
	RiskCrit  Risk = 4
)

// Finding represents a single detection result.
type Finding struct {
	Type     string `json:"type"`
	Value    string `json:"value,omitempty"`
	Position int    `json:"position"`
	Length   int    `json:"length"`
	Risk     Risk   `json:"risk"`
	Entropy  float64 `json:"entropy,omitempty"`
}

// ScanResult is the output of scanning context.
type ScanResult struct {
	RiskScore      Risk      `json:"risk_score"`
	PIIFound       []Finding `json:"pii_found"`
	SecretsFound   []Finding `json:"secrets_found"`
	Recommendation string    `json:"recommendation,omitempty"`
}

// RedactResult is the output of redacting context.
type RedactResult struct {
	Redacted       string    `json:"redacted"`
	Replacements   []Mapping `json:"replacements"`
	TokensSaved    int       `json:"tokens_saved,omitempty"`
}

// Mapping stores a single placeholder-to-original mapping.
type Mapping struct {
	Placeholder string `json:"placeholder"`
	Original    string `json:"original"`
	Type        string `json:"type"`
}

// CompressResult is the output of context compression.
type CompressResult struct {
	Compressed  string `json:"compressed"`
	TokensSaved int    `json:"tokens_saved"`
	TokensBefore int   `json:"tokens_before"`
	TokensAfter  int   `json:"tokens_after"`
}

// MemoryFilterResult validates memory before persistence.
type MemoryFilterResult struct {
	Allowed   bool     `json:"allowed"`
	Reason    string   `json:"reason,omitempty"`
	Blocked   []string `json:"blocked,omitempty"`
}

// Secret pattern definition.
type SecretPattern struct {
	Name     string
	Regex    string
	Risk     Risk
	Category string
}

// PIIPattern definition.
type PIIPattern struct {
	Name      string
	Regex     string
	Risk      Risk
	Locales   []string
	EntropyMin float64
}
