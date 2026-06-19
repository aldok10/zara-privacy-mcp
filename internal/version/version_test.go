package version

import "testing"

func TestString(t *testing.T) {
	tests := []struct {
		name    string
		version string
		commit  string
		date    string
		want    string
	}{
		{
			name:    "release version",
			version: "v1.0.0",
			commit:  "abc123",
			date:    "2026-01-01",
			want:    "v1.0.0 (abc123) built 2026-01-01",
		},
		{
			name:    "dev defaults",
			version: "dev",
			commit:  "unknown",
			date:    "unknown",
			want:    "dev (unknown) built unknown",
		},
		{
			name:    "dirty version",
			version: "v1.0.0-dirty",
			commit:  "def456",
			date:    "2026-06-19T12:00:00Z",
			want:    "v1.0.0-dirty (def456) built 2026-06-19T12:00:00Z",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Version = tt.version
			Commit = tt.commit
			Date = tt.date

			if got := String(); got != tt.want {
				t.Errorf("String() = %q; want %q", got, tt.want)
			}
		})
	}
}
