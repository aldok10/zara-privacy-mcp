package classify

import (
	"testing"

	"github.com/aldok10/zara-privacy-mcp/internal/detector"
)

func TestClassify_CriticalSecret(t *testing.T) {
	c := NewClassifier()
	result := c.Classify("some text", &detector.ScanResult{RiskScore: detector.RiskCrit})
	if result.Classification != detector.Secret {
		t.Errorf("expected SECRET, got %s", result.Classification)
	}
	if result.Confidence != 1.0 {
		t.Errorf("expected confidence 1.0, got %f", result.Confidence)
	}
}

func TestClassify_HighRisk(t *testing.T) {
	c := NewClassifier()
	result := c.Classify("some text", &detector.ScanResult{RiskScore: detector.RiskHigh})
	if result.Classification != detector.Confidential {
		t.Errorf("expected CONFIDENTIAL, got %s", result.Classification)
	}
}

func TestClassify_PasswordKeyword(t *testing.T) {
	c := NewClassifier()
	result := c.Classify("my password is here", nil)
	if result.Classification != detector.Confidential {
		t.Errorf("expected CONFIDENTIAL, got %s", result.Classification)
	}
	if result.Rule != "passwords_and_credentials" {
		t.Errorf("expected passwords_and_credentials rule, got %s", result.Rule)
	}
}

func TestClassify_PublicKeyword(t *testing.T) {
	c := NewClassifier()
	result := c.Classify("this is public information", nil)
	if result.Classification != detector.Public {
		t.Errorf("expected PUBLIC, got %s", result.Classification)
	}
}

func TestClassify_Default(t *testing.T) {
	c := NewClassifier()
	result := c.Classify("nothing special here", nil)
	if result.Classification != detector.Internal {
		t.Errorf("expected INTERNAL, got %s", result.Classification)
	}
	if result.Rule != "default" {
		t.Errorf("expected default rule, got %s", result.Rule)
	}
}

func TestClassify_FinancialData(t *testing.T) {
	c := NewClassifier()
	result := c.Classify("bank account number details", nil)
	if result.Classification != detector.Confidential {
		t.Errorf("expected CONFIDENTIAL, got %s", result.Classification)
	}
}

func TestClassify_HealthData(t *testing.T) {
	c := NewClassifier()
	result := c.Classify("patient diagnosis records", nil)
	if result.Classification != detector.Confidential {
		t.Errorf("expected CONFIDENTIAL, got %s", result.Classification)
	}
}

func TestClassify_NilScanResult(t *testing.T) {
	c := NewClassifier()
	result := c.Classify("normal text", nil)
	if result.Classification != detector.Internal {
		t.Errorf("expected INTERNAL, got %s", result.Classification)
	}
}

func TestClassificationRule_MatchAny(t *testing.T) {
	rule := ClassificationRule{
		MatchAny: []string{"foo", "bar"},
	}
	if !rule.Matches("contains foo here") {
		t.Error("expected match on foo")
	}
	if rule.Matches("no match") {
		t.Error("expected no match")
	}
}

func TestClassificationRule_MatchAll(t *testing.T) {
	rule := ClassificationRule{
		MatchAll: []string{"foo", "bar"},
	}
	if !rule.Matches("foo and bar together") {
		t.Error("expected match when both present")
	}
	if rule.Matches("only foo here") {
		t.Error("expected no match when only one present")
	}
}

func TestClassificationRule_NoPatterns(t *testing.T) {
	rule := ClassificationRule{}
	if rule.Matches("anything") {
		t.Error("expected no match with empty rule")
	}
}
