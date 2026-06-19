// Package masking provides a shared scan-and-mask helper used by all data
// proxy layers (SQL, MongoDB, Redis, HTTP). Eliminates the 4x duplication
// that previously existed across each proxy's maskValue/maskResult method.
package masking

import (
	"strings"

	"github.com/aldok10/zara-privacy-mcp/internal/detector"
)

// Result holds the masked text and findings.
type Result struct {
	Text     string
	Findings []Finding
}

// Finding describes a single masked item (for reporting to the caller).
type Finding struct {
	Column string `json:"column,omitempty"`
	Field  string `json:"field,omitempty"`
	Row    int    `json:"row"`
	Type   string `json:"type"`
	Risk   int    `json:"risk"`
}

// Masker scans and masks sensitive data using secret + PII detectors.
type Masker struct {
	secrets *detector.SecretDetector
	pii     *detector.PIIDetector
}

// New creates a Masker with the given detectors.
func New(secrets *detector.SecretDetector, pii *detector.PIIDetector) *Masker {
	return &Masker{secrets: secrets, pii: pii}
}

// MaskString scans a string value for secrets/PII and returns the masked
// version along with any findings. If no sensitive data is found, returns
// the original string unmodified with nil findings.
func (m *Masker) MaskString(val string) (string, []detector.Finding) {
	if val == "" {
		return val, nil
	}

	secrets := m.secrets.Scan(val)
	pii := m.pii.ScanWithContext(val)

	all := append(secrets, pii...)
	if len(all) == 0 {
		return val, nil
	}

	masked := val
	for _, f := range all {
		masked = strings.Replace(masked, f.Value, detector.MaskSecret(f.Value), 1)
	}

	return masked, all
}
