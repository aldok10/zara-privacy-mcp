package masking

import (
	"testing"

	"github.com/aldok10/zara-privacy-mcp/internal/detector"
)

var benchMasker = New(detector.NewSecretDetector(), detector.NewPIIDetector())

func BenchmarkMaskString_NoMatch(b *testing.B) {
	text := "This is a plain text with no sensitive data at all, just normal words."
	b.ReportAllocs()
	for b.Loop() {
		benchMasker.MaskString(text)
	}
}

func BenchmarkMaskString_Email(b *testing.B) {
	text := "Contact us at support@example.com for assistance."
	b.ReportAllocs()
	for b.Loop() {
		benchMasker.MaskString(text)
	}
}

func BenchmarkMaskString_MultipleFindings(b *testing.B) {
	text := "Email: user@test.com, Key: sk-proj-abc123def456ghi789jklmnopqrstuvwxyz, Phone: +6281234567890"
	b.ReportAllocs()
	for b.Loop() {
		benchMasker.MaskString(text)
	}
}

func BenchmarkMaskString_LargeText(b *testing.B) {
	// 1KB of text with one email buried in it
	text := make([]byte, 1024)
	for i := range text {
		text[i] = 'a'
	}
	copy(text[500:], []byte("secret@hidden.org"))
	s := string(text)
	b.ReportAllocs()
	for b.Loop() {
		benchMasker.MaskString(s)
	}
}
