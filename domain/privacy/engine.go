package privacy

type ScanResult struct {
	RiskScore      int       `json:"risk_score"`
	PIIFound       []Finding `json:"pii_found"`
	SecretsFound   []Finding `json:"secrets_found"`
	Recommendation string    `json:"recommendation"`
}

type RedactResult struct {
	Redacted     string        `json:"redacted"`
	Replacements []Replacement `json:"replacements"`
	TokensSaved  int           `json:"tokens_saved"`
}

type Replacement struct {
	Original    string `json:"original"`
	Placeholder string `json:"placeholder"`
	Type        string `json:"type"`
}

type Engine interface {
	ScanContext(text string, locales ...string) *ScanResult
	RedactContext(text string, locales ...string) *RedactResult
	UnredactResponse(text string) string
}
