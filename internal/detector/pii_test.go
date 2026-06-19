package detector

import (
	"testing"
)

func TestPIIDetection(t *testing.T) {
	det := NewPIIDetector()

	tests := []struct {
		name     string
		input    string
		locales  []string
		minFindings int
	}{
		{
			name:     "Email address",
			input:    "Contact me at user@example.com for questions",
			minFindings: 1,
		},
		{
			name:     "Indonesian NIK (KTP)",
			input:    "NIK saya 3172051234567890",
			minFindings: 1,
		},
		{
			name:     "Indonesian NPWP",
			input:    "NPWP: 12.345.678.9-012.345",
			minFindings: 1,
		},
		{
			name:     "Indonesian phone",
			input:    "Hubungi 081234567890",
			locales:  []string{"id"},
			minFindings: 1,
		},
		{
			name:     "Singapore NRIC",
			input:    "My NRIC is S1234567A",
			locales:  []string{"sg"},
			minFindings: 1,
		},
		{
			name:     "Singapore phone",
			input:    "Call me at +6591234567",
			locales:  []string{"sg"},
			minFindings: 1,
		},
		{
			name:     "Credit card number",
			input:    "My card is 4111111111111111",
			minFindings: 1,
		},
		{
			name:     "IP address",
			input:    "Server IP is 192.168.1.1 (internal, should be filtered)",
			minFindings: 0, // Should filter private IP
		},
		{
			name:     "Public IP address",
			input:    "Server IP is 203.0.113.42",
			minFindings: 1,
		},
		{
			name:     "Clean text no PII",
			input:    "Hello, this is a conversation about software engineering.",
			minFindings: 0,
		},
		{
			name:  "Multiple PII",
			input: "User: aldo@email.com, Phone: 081234567890, KTP: 3172051234567890",
			locales:  []string{"id", "global"},
			minFindings: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []Finding
			if len(tt.locales) > 0 {
				got = det.ScanWithContext(tt.input, tt.locales...)
			} else {
				got = det.ScanWithContext(tt.input)
			}

			if len(got) < tt.minFindings {
				t.Errorf("Scan(%q) got %d findings, want at least %d", tt.name, len(got), tt.minFindings)
				for i, f := range got {
					t.Logf("  finding %d: Type=%s Value=%q Risk=%d", i, f.Type, f.Value, f.Risk)
				}
			}
		})
	}
}

func TestPrivateIPFiltering(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.1", true},
		{"192.168.1.1", true},
		{"172.16.0.1", true},
		{"127.0.0.1", true},
		{"203.0.113.42", false},
		{"8.8.8.8", false},
		{"169.254.1.1", true},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := isPrivateIP(tt.ip)
			if got != tt.want {
				t.Errorf("isPrivateIP(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}
