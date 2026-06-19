package detector

import (
	"regexp"
	"strings"
)

// PIIDetector handles detection of personally identifiable information.
type PIIDetector struct {
	patterns []PIIPattern
	compiled []*regexp.Regexp
}

// NewPIIDetector creates a detector with global + Indonesia + Singapore patterns.
func NewPIIDetector() *PIIDetector {
	d := &PIIDetector{}
	d.registerBuiltin()
	d.compile()
	return d
}

func (d *PIIDetector) registerBuiltin() {
	d.patterns = []PIIPattern{
		// Global
		{Name: "Email", Regex: `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`, Risk: RiskMid, Locales: []string{"global"}},
		{Name: "Phone (Global)", Regex: `\+?[1-9][0-9]{7,15}`, Risk: RiskMid, Locales: []string{"global"}},
		{Name: "Credit Card", Regex: `\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b`, Risk: RiskHigh, Locales: []string{"global"}},
		{Name: "IP Address", Regex: `\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`, Risk: RiskLow, Locales: []string{"global"}},

		// Indonesia
		{Name: "NIK (KTP)", Regex: `\b[1-9][0-9]{15}\b`, Risk: RiskHigh, Locales: []string{"id"}},
		{Name: "NPWP", Regex: `\b[0-9]{2}\.[0-9]{3}\.[0-9]{3}\.[0-9]{1}-[0-9]{3}\.[0-9]{3}\b`, Risk: RiskHigh, Locales: []string{"id"}},
		{Name: "Passport Indonesia", Regex: `\b[A-E][0-9]{8}\b`, Risk: RiskHigh, Locales: []string{"id"}},
		{Name: "Phone Indonesia", Regex: `\b(?:(\+62|62|0)8[1-9][0-9]{7,11})\b`, Risk: RiskMid, Locales: []string{"id"}},
		{Name: "SIM Indonesia", Regex: `\b[0-9]{12,16}\b`, Risk: RiskHigh, Locales: []string{"id"}, EntropyMin: 10.0},

		// Singapore
		{Name: "NRIC Singapore", Regex: `\b[STFG]\d{7}[A-Z]\b`, Risk: RiskHigh, Locales: []string{"sg"}},
		{Name: "FIN Singapore", Regex: `\b[GM]\d{7}[A-Z]\b`, Risk: RiskHigh, Locales: []string{"sg"}},
		{Name: "Phone Singapore", Regex: `\b(?:(\+65|65)?[689][0-9]{7})\b`, Risk: RiskMid, Locales: []string{"sg"}},
		{Name: "Passport Singapore", Regex: `\b[A-Z][0-9]{8}\b`, Risk: RiskHigh, Locales: []string{"sg"}},

		// Address patterns (basic)
		{Name: "Postal Code Indonesia", Regex: `\b[1-9][0-9]{4}\b`, Risk: RiskLow, Locales: []string{"id"}},
		{Name: "Postal Code Singapore", Regex: `\b[0-9]{6}\b`, Risk: RiskLow, Locales: []string{"sg"}},

		// US
		{Name: "US SSN", Regex: `\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b`, Risk: RiskHigh, Locales: []string{"us", "global"}},

		// International
		{Name: "IBAN", Regex: `\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b`, Risk: RiskHigh, Locales: []string{"global"}},

		// Brazil
		{Name: "CPF Brazil", Regex: `\b[0-9]{3}\.[0-9]{3}\.[0-9]{3}-[0-9]{2}\b`, Risk: RiskHigh, Locales: []string{"br", "global"}},
	}
}

func (d *PIIDetector) compile() {
	d.compiled = make([]*regexp.Regexp, len(d.patterns))
	for i, p := range d.patterns {
		d.compiled[i] = regexp.MustCompile(p.Regex)
	}
}

// Scan runs all PII detectors against the input text.
// If locales is empty, scans all locales.
func (d *PIIDetector) Scan(text string, locales ...string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	localeSet := make(map[string]bool)
	for _, l := range locales {
		localeSet[l] = true
	}
	scanAll := len(locales) == 0

	for i, pattern := range d.patterns {
		// Skip if filtering by locale and this pattern doesn't match
		if !scanAll && !localeSet["global"] {
			match := false
			for _, pl := range pattern.Locales {
				if localeSet[pl] {
					match = true
					break
				}
			}
			if !match {
				continue
			}
		}

		matches := d.compiled[i].FindAllStringSubmatchIndex(text, -1)
		for _, match := range matches {
			start := match[0]
			end := match[1]
			if start == -1 {
				continue
			}

			value := text[start:end]

			// Deduplicate
			if seen[value] {
				continue
			}
			seen[value] = true

			// Check entropy floor if set
			if pattern.EntropyMin > 0 {
				if shannonEntropy(value) < pattern.EntropyMin {
					continue
				}
			}

			// Skip IP addresses that are clearly private/internal
			if pattern.Name == "IP Address" && isPrivateIP(value) {
				continue
			}

			findings = append(findings, Finding{
				Type:     pattern.Name,
				Value:    value,
				Position: start,
				Length:   end - start,
				Risk:     pattern.Risk,
			})
		}
	}

	return findings
}

// isPrivateIP checks if an IP address is in private ranges.
func isPrivateIP(ip string) bool {
	// Simple prefix check for common private ranges
	prefixes := []string{"10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
		"172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
		"172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
		"127.", "0.", "169.254."}
	for _, p := range prefixes {
		if strings.HasPrefix(ip, p) {
			return true
		}
	}
	return false
}

// ScanWithContext scans PII with awareness of surrounding text.
// This reduces false positives by checking context.
func (d *PIIDetector) ScanWithContext(text string, locales ...string) []Finding {
	findings := d.Scan(text, locales...)

	// Post-processing: filter findings based on context
	var filtered []Finding
	for _, f := range findings {
		// Skip short numeric-only findings that look like years or simple numbers
		if isFalsePositive(f, text) {
			continue
		}
		filtered = append(filtered, f)
	}

	return filtered
}

// isFalsePositive checks if a finding is likely a false positive.
func isFalsePositive(f Finding, text string) bool {
	// Get context around the finding
	start := max(f.Position-20, 0)
	end := min(f.Position+f.Length+20, len(text))
	ctx := strings.ToLower(text[start:end])

	// Check if it looks like a year (4 digits, 1900-2099)
	if f.Type == "NIK (KTP)" || f.Type == "SIM Indonesia" {
		if len(f.Value) == 4 {
			return true // Likely a year, not PII
		}
	}

	// Postal code false positives
	if strings.Contains(f.Type, "Postal Code") {
		// Check if preceded by context suggesting non-PII usage
		nonPII := []string{"port", "zip", "postal", "kode pos", "kode"}
		for _, keyword := range nonPII {
			if strings.Contains(ctx, keyword) {
				return false // Actual postal code
			}
		}
		// Short numbers are usually not postal codes
		if len(f.Value) < 5 {
			return true
		}
	}

	return false
}
