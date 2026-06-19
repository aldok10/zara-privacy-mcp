package http

import "testing"

func TestValidateURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{name: "public https", url: "https://api.github.com/repos", wantErr: false},
		{name: "public http", url: "http://example.com/path", wantErr: false},

		{name: "localhost", url: "http://127.0.0.1/admin", wantErr: true},
		{name: "private 10.x", url: "http://10.0.0.1/internal", wantErr: true},
		{name: "private 172.16.x", url: "http://172.16.0.1/api", wantErr: true},
		{name: "private 192.168.x", url: "http://192.168.1.1/config", wantErr: true},

		{name: "aws metadata", url: "http://169.254.169.254/latest/meta-data", wantErr: true},
		{name: "alibaba metadata", url: "http://100.100.100.200/meta-data", wantErr: true},
		{name: "gcp metadata", url: "http://metadata.google.internal/computeMetadata", wantErr: true},

		{name: "file scheme", url: "file:///etc/passwd", wantErr: true},
		{name: "ftp scheme", url: "ftp://evil.com/data", wantErr: true},

		{name: "empty url", url: "", wantErr: true},
		{name: "no scheme", url: "just-a-string", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateURL(%q) error = %v; wantErr = %v", tt.url, err, tt.wantErr)
			}
		})
	}
}
