package masking

import (
	"testing"

	"github.com/aldok10/zara-privacy-mcp/internal/detector"
)

func TestMaskString(t *testing.T) {
	m := New(detector.NewSecretDetector(), detector.NewPIIDetector())

	tests := []struct {
		name         string
		input        string
		wantMasked   bool
		wantFindings int
	}{
		{"empty string", "", false, 0},
		{"no sensitive data", "hello world", false, 0},
		{"email detected", "contact budi@example.com please", true, 1},
		{"api key detected", "key is sk-proj-abc123def456ghi789jklmnopqrstuvwxyz", true, 1},
		{"multiple findings", "email: test@x.com and key sk-proj-abc123def456ghi789jklmnop", true, 2},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			masked, findings := m.MaskString(tc.input)
			if tc.wantMasked && masked == tc.input {
				t.Error("expected text to be masked")
			}
			if !tc.wantMasked && masked != tc.input {
				t.Errorf("expected no masking, got %q", masked)
			}
			if len(findings) < tc.wantFindings {
				t.Errorf("want >= %d findings, got %d", tc.wantFindings, len(findings))
			}
		})
	}
}
