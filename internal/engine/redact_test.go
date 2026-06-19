package engine

import (
	"os"
	"testing"

	"github.com/aldok10/zara-privacy-mcp/internal/detector"
	"github.com/aldok10/zara-privacy-mcp/internal/store"
)

func TestScanAndRedact(t *testing.T) {
	// Setup
	secretDet := detector.NewSecretDetector()
	piiDet := detector.NewPIIDetector()

	ms, err := store.NewMappingStore(os.TempDir()+"/test_zara_mcp.db", []byte("test-key-32-bytes-long-for-testing!"))
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer ms.Close()
	defer os.Remove(os.TempDir() + "/test_zara_mcp.db")

	engine := NewRedactEngine(secretDet, piiDet, ms)

	t.Run("scan detects secrets", func(t *testing.T) {
		result := engine.ScanContext("My API key is sk-proj-ABCDefghijklmnopqrstuvwxyz123456")
		if len(result.SecretsFound) == 0 {
			t.Error("Expected to find secrets")
		}
		if result.RiskScore < detector.RiskHigh {
			t.Errorf("Expected high or critical risk, got %d", result.RiskScore)
		}
	})

	t.Run("scan detects PII", func(t *testing.T) {
		result := engine.ScanContext("Email me at test@example.com")
		if len(result.PIIFound) == 0 {
			t.Error("Expected to find PII")
		}
	})

	t.Run("redact replaces and unredact restores", func(t *testing.T) {
		original := "My email is user@example.com and my API key is sk-proj-ABCDefghijklmnopqrstuvwxyz123456"
		redactResult := engine.RedactContext(original)

		if redactResult.Redacted == original {
			t.Error("Redaction did not change the text")
		}

		// Verify placeholders present
		if !containsPlaceholder(redactResult.Redacted) {
			t.Errorf("Redacted text should contain placeholders, got: %s", redactResult.Redacted)
		}

		// Unredact
		restored := engine.UnredactResponse(redactResult.Redacted)
		if restored != original {
			t.Errorf("Unredact mismatch:\n  original: %s\n  restored: %s", original, restored)
		}
	})

	t.Run("empty text returns empty", func(t *testing.T) {
		result := engine.RedactContext("")
		if result.Redacted != "" {
			t.Error("Empty input should produce empty output")
		}
	})

	t.Run("clean text unchanged", func(t *testing.T) {
		original := "Hello, this is a normal conversation about programming."
		result := engine.RedactContext(original)
		if result.Redacted != original {
			t.Errorf("Clean text should remain unchanged, got: %s", result.Redacted)
		}
	})

	t.Run("unredact with no placeholders", func(t *testing.T) {
		original := "Hello, this is a normal message."
		restored := engine.UnredactResponse(original)
		if restored != original {
			t.Errorf("Unchanged text should remain: %s", restored)
		}
	})
}

func TestOverlappingDetection(t *testing.T) {
	secretDet := detector.NewSecretDetector()
	piiDet := detector.NewPIIDetector()

	ms, err := store.NewMappingStore(os.TempDir()+"/test_zara_overlap.db", []byte("test-key-32-bytes-long-for-testing!"))
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer ms.Close()
	defer os.Remove(os.TempDir() + "/test_zara_overlap.db")

	engine := NewRedactEngine(secretDet, piiDet, ms)

	t.Run("overlapping findings deduplicated", func(t *testing.T) {
		// "Bearer token" and "JWT" both match on similar content
		text := "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8"

		findings := engine.collectAllFindings(text)
		// Should not have overlapping duplicates
		seenPositions := make(map[int]bool)
		for _, f := range findings {
			if seenPositions[f.Position] {
				t.Errorf("Duplicate position %d for finding %s", f.Position, f.Type)
			}
			seenPositions[f.Position] = true
		}
	})
}

func containsPlaceholder(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '[' {
			for j := i + 1; j < len(s); j++ {
				if s[j] == ']' {
					return true
				}
			}
		}
	}
	return false
}
