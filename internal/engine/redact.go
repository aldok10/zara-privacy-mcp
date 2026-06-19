// Package engine orchestrates detection, redaction, and unredaction.
package engine

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aldok10/zara-privacy-mcp/internal/detector"
	"github.com/aldok10/zara-privacy-mcp/internal/store"
)

// RedactEngine orchestrates scanning, redaction, and unredaction.
type RedactEngine struct {
	secretDetector *detector.SecretDetector
	piiDetector    *detector.PIIDetector
	mappingStore   *store.MappingStore
}

// NewRedactEngine creates a fully initialized redaction engine.
func NewRedactEngine(secretDet *detector.SecretDetector, piiDet *detector.PIIDetector, ms *store.MappingStore) *RedactEngine {
	return &RedactEngine{
		secretDetector: secretDet,
		piiDetector:    piiDet,
		mappingStore:   ms,
	}
}

// ScanContext scans text for secrets and PII, returns findings with risk score.
func (e *RedactEngine) ScanContext(text string, locales ...string) *detector.ScanResult {
	secrets := e.secretDetector.Scan(text)
	pii := e.piiDetector.ScanWithContext(text, locales...)

	result := &detector.ScanResult{
		PIIFound:     pii,
		SecretsFound: secrets,
	}

	// Calculate overall risk score
	maxRisk := detector.RiskNone
	for _, f := range secrets {
		if f.Risk > maxRisk {
			maxRisk = f.Risk
		}
	}
	for _, f := range pii {
		if f.Risk > maxRisk {
			maxRisk = f.Risk
		}
	}
	result.RiskScore = maxRisk

	// Generate recommendation
	result.Recommendation = generateRecommendation(result)

	return result
}

// RedactContext replaces detected secrets and PII with placeholders.
func (e *RedactEngine) RedactContext(text string, locales ...string) *detector.RedactResult {
	findings := e.collectAllFindings(text, locales...)

	// Sort findings by position descending so replacements don't shift indices
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Position > findings[j].Position
	})

	var replacements []detector.Mapping
	result := text

	for _, f := range findings {
		mapping := e.mappingStore.GetOrCreate(f.Value, f.Type)
		result = result[:f.Position] + mapping.Placeholder + result[f.Position+f.Length:]
		replacements = append(replacements, mapping)
	}

	// Estimate tokens saved
	tokensSaved := 0
	for _, r := range replacements {
		originalTokens := estimateTokens(r.Original)
		placeholderTokens := estimateTokens(r.Placeholder)
		tokensSaved += originalTokens - placeholderTokens
	}

	return &detector.RedactResult{
		Redacted:     result,
		Replacements: replacements,
		TokensSaved:  tokensSaved,
	}
}

// UnredactResponse restores original values in an LLM response.
func (e *RedactEngine) UnredactResponse(text string) string {
	var result strings.Builder
	i := 0
	for i < len(text) {
		start := strings.Index(text[i:], "[")
		if start == -1 {
			result.WriteString(text[i:])
			break
		}
		// Write everything before the bracket
		result.WriteString(text[i : i+start])

		end := strings.Index(text[i+start:], "]")
		if end == -1 {
			result.WriteString(text[i+start:])
			break
		}
		end += i + start + 1
		placeholder := text[i+start : end]

		mapping, ok := e.mappingStore.Lookup(placeholder)
		if ok {
			result.WriteString(mapping.Original)
		} else {
			// Keep unknown brackets intact (don't corrupt text)
			result.WriteString(placeholder)
		}
		i = end
	}
	return result.String()
}

// collectAllFindings gathers all secrets and PII from text.
func (e *RedactEngine) collectAllFindings(text string, locales ...string) []detector.Finding {
	secrets := e.secretDetector.Scan(text)
	pii := e.piiDetector.ScanWithContext(text, locales...)

	all := append(secrets, pii...)

	// Sort by position for consistent processing
	sort.Slice(all, func(i, j int) bool {
		return all[i].Position < all[j].Position
	})

	// Remove overlapping findings (keep the higher risk one)
	return deduplicateOverlapping(all)
}

// deduplicateOverlapping removes overlapping findings, keeping higher risk ones.
func deduplicateOverlapping(findings []detector.Finding) []detector.Finding {
	if len(findings) == 0 {
		return findings
	}

	var result []detector.Finding
	for _, f := range findings {
		overlap := false
		for i, existing := range result {
			if overlapRanges(existing.Position, existing.Length, f.Position, f.Length) {
				overlap = true
				// Keep the higher risk one
				if f.Risk > existing.Risk {
					result[i] = f
				}
				break
			}
		}
		if !overlap {
			result = append(result, f)
		}
	}

	return result
}

func overlapRanges(pos1, len1, pos2, len2 int) bool {
	return pos1 < pos2+len2 && pos2 < pos1+len1
}

// generateRecommendation creates a human-readable recommendation.
func generateRecommendation(result *detector.ScanResult) string {
	total := len(result.PIIFound) + len(result.SecretsFound)
	if total == 0 {
		return "No sensitive data detected. Context is safe to send."
	}

	riskLabel := "PASS"
	switch {
	case result.RiskScore >= detector.RiskCrit:
		riskLabel = "CRITICAL"
	case result.RiskScore >= detector.RiskHigh:
		riskLabel = "HIGH"
	case result.RiskScore >= detector.RiskMid:
		riskLabel = "MEDIUM"
	case result.RiskScore >= detector.RiskLow:
		riskLabel = "LOW"
	}

	var parts []string
	if len(result.SecretsFound) > 0 {
		parts = append(parts, fmt.Sprintf("%d secret(s) detected", len(result.SecretsFound)))
	}
	if len(result.PIIFound) > 0 {
		parts = append(parts, fmt.Sprintf("%d PII field(s) found", len(result.PIIFound)))
	}

	return fmt.Sprintf("Risk level: %s. %s Use redact_context before sending to LLM.",
		riskLabel, strings.Join(parts, ", "))
}

// estimateTokens roughly estimates token count for a string.
// ~4 characters per token for English, ~2 for Indonesian.
func estimateTokens(s string) int {
	// Simple heuristic: count words and special chars
	words := strings.Fields(s)
	charCount := len(s)

	// Estimate: 1 token ≈ 4 chars
	tokens := max(charCount/4, len(words))
	if tokens < 1 {
		tokens = 1
	}
	return tokens
}
