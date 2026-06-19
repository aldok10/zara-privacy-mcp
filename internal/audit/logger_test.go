package audit

import (
	"os"
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantNil bool
	}{
		{name: "empty path returns nil", path: "", wantNil: true},
		{name: "valid path returns logger", path: t.TempDir() + "/a.log", wantNil: false},
		{name: "invalid path returns nil", path: "/nonexistent/dir/x/y/z.log", wantNil: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := New(tt.path)
			if (l == nil) != tt.wantNil {
				t.Errorf("New(%q) nil=%v; want nil=%v", tt.path, l == nil, tt.wantNil)
			}
			if l != nil {
				l.Close()
			}
		})
	}
}

func TestLogBlocked(t *testing.T) {
	tests := []struct {
		name       string
		tool       string
		reason     string
		wantInLog  []string
	}{
		{
			name:      "db_query blocked",
			tool:      "db_query",
			reason:    "DROP TABLE",
			wantInLog: []string{"BLOCKED", "db_query", "DROP TABLE"},
		},
		{
			name:      "redis blocked",
			tool:      "redis_exec",
			reason:    "FLUSHALL not allowed",
			wantInLog: []string{"BLOCKED", "redis_exec", "FLUSHALL"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := t.TempDir() + "/audit.log"
			l := New(path)
			defer l.Close()

			l.LogBlocked(tt.tool, tt.reason)

			data, _ := os.ReadFile(path)
			for _, want := range tt.wantInLog {
				if !strings.Contains(string(data), want) {
					t.Errorf("log missing %q; got %q", want, string(data))
				}
			}
		})
	}
}

func TestNilSafety(t *testing.T) {
	var l *Logger
	// These must not panic
	l.LogBlocked("test", "reason")
	l.Close()
}
