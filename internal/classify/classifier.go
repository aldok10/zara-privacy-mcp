// Package classify provides data classification capabilities.
// Phase 3: classify data by sensitivity level (Public → Secret).
package classify

import (
	"github.com/aldok10/zara-privacy-mcp/internal/detector"
)

// Classifier analyzes data and assigns a sensitivity classification.
// Phase 3 will add:
//   - Content-based classification (ML model)
//   - Context-aware classification (sender, recipient, intent)
//   - Custom classification rules
//   - Confidence scoring
type Classifier struct {
	rules []ClassificationRule
}

// ClassificationRule defines a rule for classifying data.
type ClassificationRule struct {
	Name           string
	Description    string
	MatchAny       []string
	MatchAll       []string
	Classification detector.Classification
	Priority       int
}

// NewClassifier creates a classifier with default rules.
func NewClassifier() *Classifier {
	return &Classifier{
		rules: defaultRules(),
	}
}

// ClassifyResult is the output of classification.
type ClassifyResult struct {
	Classification detector.Classification `json:"classification"`
	Rule           string                  `json:"rule,omitempty"`
	Confidence     float64                 `json:"confidence"`
	Matches        []string                `json:"matches,omitempty"`
}

// Classify assigns a classification to the given text.
func (c *Classifier) Classify(text string, scanResult *detector.ScanResult) ClassifyResult {
	// If scan found critical secrets, always classify as SECRET
	if scanResult != nil && scanResult.RiskScore >= detector.RiskCrit {
		return ClassifyResult{
			Classification: detector.Secret,
			Rule:           "critical_secret_detected",
			Confidence:     1.0,
		}
	}

	if scanResult != nil && scanResult.RiskScore >= detector.RiskHigh {
		return ClassifyResult{
			Classification: detector.Confidential,
			Rule:           "high_risk_data_detected",
			Confidence:     0.95,
		}
	}

	// Check rules
	for _, rule := range c.rules {
		if rule.Matches(text) {
			return ClassifyResult{
				Classification: rule.Classification,
				Rule:           rule.Name,
				Confidence:     0.8,
			}
		}
	}

	return ClassifyResult{
		Classification: detector.Internal,
		Rule:           "default",
		Confidence:     0.5,
	}
}

// Matches checks if text matches the rule.
func (r *ClassificationRule) Matches(text string) bool {
	// Simple keyword matching (Phase 3 will improve)
	if len(r.MatchAny) > 0 {
		for _, kw := range r.MatchAny {
			if contains(text, kw) {
				return true
			}
		}
		return false
	}

	if len(r.MatchAll) > 0 {
		for _, kw := range r.MatchAll {
			if !contains(text, kw) {
				return false
			}
		}
		return len(r.MatchAll) > 0
	}

	return false
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func defaultRules() []ClassificationRule {
	return []ClassificationRule{
		{
			Name:           "passwords_and_credentials",
			Description:    "Contains password, credential, or login information",
			MatchAny:       []string{"password", "credential", "login", "signin", "sign-in"},
			Classification: detector.Confidential,
			Priority:       100,
		},
		{
			Name:           "financial_data",
			Description:    "Contains financial or banking information",
			MatchAny:       []string{"bank", "account number", "routing", "swift", "bic"},
			Classification: detector.Confidential,
			Priority:       90,
		},
		{
			Name:           "health_data",
			Description:    "Contains health or medical information",
			MatchAny:       []string{"diagnosis", "patient", "medical", "health record"},
			Classification: detector.Confidential,
			Priority:       80,
		},
		{
			Name:           "internal_discussion",
			Description:    "Internal team or company discussion",
			MatchAny:       []string{"internal", "confidential", "proprietary", "private"},
			Classification: detector.Internal,
			Priority:       70,
		},
		{
			Name:           "public_information",
			Description:    "Public or general information",
			MatchAny:       []string{"public", "open source", "readme"},
			Classification: detector.Public,
			Priority:       10,
		},
	}
}
