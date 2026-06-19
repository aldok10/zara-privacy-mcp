package detector

import (
	"testing"
)

func TestOpenAIKeyDetection(t *testing.T) {
	det := NewSecretDetector()

	tests := []struct {
		name  string
		input string
		want  int // expected number of findings
	}{
		{
			name:  "OpenAI API key",
			input: "sk-proj-rAnd0mT3xtT0k3nF0rT3st1ngPurp0ses0nly12345678",
			want:  1,
		},
		{
			name:  "OpenAI API key with context",
			input: `export OPENAI_API_KEY="sk-proj-RandomKeyForTestingPurposesOnly123456789"`,
			want:  1,
		},
		{
			name:  "Anthropic API key",
			input: "sk-ant-auth0aNtHr0p1cK3yTh4t1sV3ryL0ng4ndS3cur3F0rT3st1ng",
			want:  1,
		},
		{
			name:  "Gemini API key",
			input: "AIzaSyDummyKey12345ForTestingPurposes67890abcdef",
			want:  1,
		},
		{
			name:  "AWS access key",
			input: "AKIAIOSFODNN7EXAMPLE",
			want:  1,
		},
		{
			name:  "JWT token",
			input: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8",
			want:  1,
		},
		{
			name:  "Bearer token",
			input: "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8",
			want:  2, // JWT + Bearer
		},
		{
			name:  "SSH private key header",
			input: "-----BEGIN OPENSSH PRIVATE KEY-----",
			want:  1,
		},
		{
			name:  "Database URL",
			input: "postgres://user:password123@localhost:5432/mydb",
			want:  1,
		},
		{
			name:  "MongoDB URL",
			input: "mongodb+srv://admin:secretpass@cluster0.abcde.mongodb.net",
			want:  1,
		},
		{
			name:  "No secrets - clean text",
			input: "Hello, how are you? Today is a great day for coding.",
			want:  0,
		},
		{
			name:  "No secrets - code snippet",
			input: `function hello() { console.log("Hello, world!"); }`,
			want:  0,
		},
		{
			name:  "Multiple secrets in one message",
			input: `OPENAI_KEY=sk-proj-ABCDefghijklmnopqrstuvwxyz123456 GitHub token plus postgres://admin:pass@db:5432/test`,
			want:  2, // OpenAI key + DB URL
		},
		{
			name:  "URL with credentials",
			input: "https://admin:secret123@api.example.com/v1/data",
			want:  1, // URL with credentials
		},
		{
			name:  "Short random string (low entropy, skip)",
			input: "hello-world-test",
			want:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := det.Scan(tt.input)
			if len(got) != tt.want {
				t.Errorf("Scan(%q) got %d findings, want %d", tt.name, len(got), tt.want)
				for i, f := range got {
					t.Logf("  finding %d: Type=%s Risk=%d Entropy=%.2f", i, f.Type, f.Risk, f.Entropy)
				}
			}
		})
	}
}
func TestHighEntropyDetection(t *testing.T) {
	tests := []struct {
		input     string
		threshold float64
		want      bool
	}{
		{"aB3dE5gH7jK9mL0nP2qR4sT6vW8xY1zC5", 4.0, true},        // random-like
		{"hello-world-simple-text-nothing-special", 4.0, false}, // low entropy
		{"sk-proj-RandomKeyForTestingOnly12345678", 4.0, true},
		{"short", 4.0, false}, // too short
	}

	for _, tt := range tests {
		t.Run(tt.input[:min(len(tt.input), 20)], func(t *testing.T) {
			got := IsHighEntropy(tt.input, tt.threshold)
			if got != tt.want {
				t.Errorf("IsHighEntropy(%q, %.1f) = %v, want %v", tt.input, tt.threshold, got, tt.want)
			}
		})
	}
}

func TestMaskSecret(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// len=21: first 4 + 13 stars + last 4
		{"sk-proj-RandomKeyHere", "sk-p*************Here"},
		// len=2 <= 8 => all stars
		{"ab", "**"},
		{"abcdefgh", "********"},
		// len=10: first 4 + 2 stars + last 4
		{"abcdefghij", "abcd**ghij"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := MaskSecret(tt.input)
			if got != tt.want {
				t.Errorf("MaskSecret(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
