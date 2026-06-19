// Package engine orchestrates detection, redaction, and unredaction.
package engine

import (
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
	for {
		start := strings.Index(text, "[")
		if start == -1 {
			break
		}
		end := strings.Index(text[start:], "]")
		if end == -1 {
			break
		}
		end += start + 1
		placeholder := text[start:end]

		mapping, ok := e.mappingStore.Lookup(placeholder)
		if !ok {
			// Skip unknown placeholders
			text = text[:start] + text[end:]
			continue
		}

		text = text[:start] + mapping.Original + text[end:]
	}

	return text
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

	var parts []string

	if len(result.SecretsFound) > 0 {
		risks := make(map[string]int)
		for _, f := range result.SecretsFound {
			risks[string(f.Type)]++
		}
		for t, c := range risks {
			parts = append(parts, "%d %s(s) found")
			_ = t
			_ = c
		}
		parts = append(parts, "%d secrets detected")
	}

	if len(result.PIIFound) > 0 {
		parts = append(parts, "%d PII fields detected")
	}

	riskLabel := "PASS"
	if result.RiskScore >= detector.RiskCrit {
		riskLabel = "CRITICAL"
	} else if result.RiskScore >= detector.RiskHigh {
		riskLabel = "HIGH"
	} else if result.RiskScore >= detector.RiskMid {
		riskLabel = "MEDIUM"
	} else if result.RiskScore >= detector.RiskLow {
		riskLabel = "LOW"
	}

	var sb strings.Builder
	sb.WriteString("Risk level: ")
	sb.WriteString(riskLabel)
	sb.WriteString(". ")
	sb.WriteString(strings.Join(parts, ", "))
	sb.WriteString(". Use redact_context before sending to LLM.")
	return sb.String()
}

// estimateTokens roughly estimates token count for a string.
// ~4 characters per token for English, ~2 for Indonesian.
func estimateTokens(s string) int {
	// Simple heuristic: count words and special chars
	words := strings.Fields(s)
	charCount := len(s)

	// Estimate: 1 token ≈ 4 chars
	tokens := charCount / 4
	if tokens < len(words) {
		tokens = len(words)
	}
	if tokens < 1 {
		tokens = 1
	}
	return tokens
}
