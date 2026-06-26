package detector

import (
	"encoding/json"
	"math"
	"os"
	"regexp"
	"strings"
)

// SecretDetector handles detection of secrets, API keys, and credentials.
type SecretDetector struct {
	patterns []SecretPattern
	compiled []*regexp.Regexp
}

// NewSecretDetector creates a detector with all known secret patterns.
func NewSecretDetector() *SecretDetector {
	d := &SecretDetector{}
	d.registerBuiltin()
	d.compile()
	return d
}

func (d *SecretDetector) registerBuiltin() {
	d.patterns = []SecretPattern{
		// OpenAI — project keys (sk-proj-...) and standard keys (sk-...)
		{Name: "OpenAI API Key", Regex: `sk-proj-[A-Za-z0-9]{20,60}`, Risk: RiskCrit, Category: "API Key"},
		{Name: "OpenAI API Key (legacy)", Regex: `sk-[A-Za-z0-9]{20,50}T3BlbkFJ[A-Za-z0-9]{20,50}`, Risk: RiskCrit, Category: "API Key"},
		{Name: "OpenAI API Key (short)", Regex: `\bsk-[A-Za-z0-9]{32,64}\b`, Risk: RiskCrit, Category: "API Key"},
		{Name: "OpenAI Org Key", Regex: `org-[A-Za-z0-9]{20,50}`, Risk: RiskHigh, Category: "API Key"},

		// Anthropic
		{Name: "Anthropic API Key", Regex: `sk-ant-[A-Za-z0-9]{40,100}`, Risk: RiskCrit, Category: "API Key"},

		// Gemini
		{Name: "Gemini API Key", Regex: `AIza[A-Za-z0-9\-_]{35,50}`, Risk: RiskCrit, Category: "API Key"},

		// DeepSeek
		{Name: "DeepSeek API Key", Regex: `sk-[a-f0-9]{32,64}`, Risk: RiskCrit, Category: "API Key"},

		// Groq
		{Name: "Groq API Key", Regex: `gsk_[A-Za-z0-9]{20,60}`, Risk: RiskCrit, Category: "API Key"},

		// Mistral
		{Name: "Mistral API Key", Regex: `\bmistral[_-][A-Za-z0-9]{32,64}\b`, Risk: RiskCrit, Category: "API Key"},

		// Cohere
		{Name: "Cohere API Key", Regex: `\bco-[A-Za-z0-9]{40,60}\b`, Risk: RiskCrit, Category: "API Key"},

		// Fireworks AI
		{Name: "Fireworks API Key", Regex: `fw_[A-Za-z0-9]{20,60}`, Risk: RiskCrit, Category: "API Key"},

		// Together AI
		{Name: "Together API Key", Regex: `tog-[A-Za-z0-9]{40,80}`, Risk: RiskCrit, Category: "API Key"},

		// Perplexity
		{Name: "Perplexity API Key", Regex: `pplx-[A-Za-z0-9]{40,80}`, Risk: RiskCrit, Category: "API Key"},

		// OpenRouter
		{Name: "OpenRouter API Key", Regex: `sk-or-v1-[A-Za-z0-9]{40,80}`, Risk: RiskCrit, Category: "API Key"},

		// AWS
		{Name: "AWS Access Key", Regex: `AKIA[0-9A-Z]{16}`, Risk: RiskCrit, Category: "AWS"},
		{Name: "AWS Secret Key", Regex: `(?i)aws(.{0,20})?(?:key|secret)?['"?\s]?[:=]['"?\s]?([A-Za-z0-9\/+=]{40,60})`, Risk: RiskCrit, Category: "AWS"},

		// JWT
		{Name: "JWT Token", Regex: `eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+`, Risk: RiskHigh, Category: "Token"},

		// Bearer Tokens
		{Name: "Bearer Token", Regex: `(?i)bearer\s+[A-Za-z0-9\-_.]{20,200}`, Risk: RiskHigh, Category: "Token"},

		// SSH & PEM Keys
		{Name: "SSH Private Key", Regex: `-----BEGIN OPENSSH PRIVATE KEY-----`, Risk: RiskCrit, Category: "Private Key"},
		{Name: "RSA Private Key", Regex: `-----BEGIN RSA PRIVATE KEY-----`, Risk: RiskCrit, Category: "Private Key"},
		{Name: "EC Private Key", Regex: `-----BEGIN EC PRIVATE KEY-----`, Risk: RiskCrit, Category: "Private Key"},
		{Name: "Generic PEM Key", Regex: `-----BEGIN [A-Z ]+PRIVATE KEY-----`, Risk: RiskCrit, Category: "Private Key"},
		{Name: "PEM Certificate", Regex: `-----BEGIN CERTIFICATE-----`, Risk: RiskMid, Category: "Certificate"},

		// Database URLs
		{Name: "PostgreSQL URL", Regex: `postgres(?:ql)?:\/\/[^:\s]+:[^@\s]+@[^\/\s]+`, Risk: RiskHigh, Category: "Database"},
		{Name: "MySQL URL", Regex: `mysql:\/\/[^:\s]+:[^@\s]+@[^\/\s]+`, Risk: RiskHigh, Category: "Database"},
		{Name: "MongoDB URL", Regex: `mongodb(?:\+srv)?:\/\/[^:\s]+:[^@\s]+@[^\/\s]+`, Risk: RiskHigh, Category: "Database"},
		{Name: "Redis URL", Regex: `redis:\/\/[^:\s]+:[^@\s]+@[^\/\s]+`, Risk: RiskHigh, Category: "Database"},

		// URLs with embedded credentials
		{Name: "URL with Credentials", Regex: `https?:\/\/[^:\/\s]+:[^@\s]+@[^\s]+`, Risk: RiskHigh, Category: "URL"},

		// Session & OAuth
		{Name: "Session Cookie", Regex: `(?i)(session|auth|token|sid)[=:]['"]?[A-Za-z0-9]{20,100}['"]?`, Risk: RiskMid, Category: "Cookie"},
		{Name: "OAuth Token", Regex: `(?i)(oauth_token|access_token|refresh_token)[=:]['"]?[A-Za-z0-9\-_.]{20,200}['"]?`, Risk: RiskHigh, Category: "OAuth"},

		// Generic high-entropy tokens (fallback)
		{Name: "High Entropy Token", Regex: `[A-Za-z0-9\-_.]{40,120}`, Risk: RiskLow, Category: "Generic"},
	}
}

func (d *SecretDetector) compile() {
	d.compiled = make([]*regexp.Regexp, len(d.patterns))
	for i, p := range d.patterns {
		d.compiled[i] = regexp.MustCompile(p.Regex)
	}
}

// CustomRule defines a user-configurable detection rule (JSON format).
type CustomRule struct {
	Name     string `json:"name"`
	Pattern  string `json:"pattern"`
	Severity string `json:"severity"` // "low", "mid", "high", "critical"
	Category string `json:"category"`
}

// LoadCustomRules loads additional detection patterns from a JSON file.
// File format: [{"name": "...", "pattern": "...", "severity": "high", "category": "..."}]
func (d *SecretDetector) LoadCustomRules(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var rules []CustomRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return err
	}

	for _, r := range rules {
		// Validate regex compiles
		if _, err := regexp.Compile(r.Pattern); err != nil {
			continue
		}
		risk := RiskMid
		switch strings.ToLower(r.Severity) {
		case "low":
			risk = RiskLow
		case "mid", "medium":
			risk = RiskMid
		case "high":
			risk = RiskHigh
		case "critical", "crit":
			risk = RiskCrit
		}
		d.patterns = append(d.patterns, SecretPattern{
			Name: r.Name, Regex: r.Pattern, Risk: risk, Category: r.Category,
		})
	}

	// Recompile with new patterns
	d.compile()
	return nil
}

// Scan runs all secret detectors against the input text.
func (d *SecretDetector) Scan(text string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for i, pattern := range d.patterns {
		matches := d.compiled[i].FindAllStringSubmatchIndex(text, -1)
		for _, match := range matches {
			start := match[0]
			end := match[1]
			if start == -1 {
				continue
			}

			// Extract the actual matched value
			var value string
			if len(match) > 2 && match[2] != -1 {
				// Use capturing group if available
				value = text[match[2]:match[3]]
			} else {
				value = text[start:end]
			}

			// Deduplicate
			if seen[value] {
				continue
			}
			seen[value] = true

			// Calculate entropy for generic patterns
			entropy := 0.0
			if pattern.Category == "Generic" {
				entropy = shannonEntropy(value)
				if entropy < 4.0 {
					continue // Low entropy, likely not a secret
				}
			}

			findings = append(findings, Finding{
				Type:     pattern.Name,
				Value:    value,
				Position: start,
				Length:   end - start,
				Risk:     pattern.Risk,
				Entropy:  entropy,
			})
		}
	}

	return findings
}

// shannonEntropy calculates Shannon entropy of a string.
// Higher entropy indicates more random-like strings (potential secrets).
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]float64)
	for _, r := range s {
		freq[r]++
	}

	var entropy float64
	for _, count := range freq {
		p := count / float64(len(s))
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// IsHighEntropy checks if a string has high entropy (likely a secret).
func IsHighEntropy(s string, threshold float64) bool {
	if len(s) < 20 {
		return false
	}
	return shannonEntropy(s) >= threshold
}

// MaskSecret partially masks a secret for safe display.
func MaskSecret(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + strings.Repeat("*", len(s)-8) + s[len(s)-4:]
}
