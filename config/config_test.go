package config

import (
	"os"
	"testing"
)

func TestLoad_Defaults(t *testing.T) {
	cfg := Load()
	if cfg.Port != "8530" {
		t.Errorf("want default port 8530, got %s", cfg.Port)
	}
	if cfg.Host != "127.0.0.1" {
		t.Errorf("want default host 127.0.0.1, got %s", cfg.Host)
	}
	if cfg.MaxTokens != 4096 {
		t.Errorf("want default max tokens 4096, got %d", cfg.MaxTokens)
	}
}

func TestLoad_DatabaseFromEnv(t *testing.T) {
	os.Setenv("ZARA_DB_TEST_DRIVER", "sqlite")
	os.Setenv("ZARA_DB_TEST_DSN", "/tmp/test.db")
	defer os.Unsetenv("ZARA_DB_TEST_DRIVER")
	defer os.Unsetenv("ZARA_DB_TEST_DSN")

	cfg := Load()
	db, ok := cfg.Databases["TEST"]
	if !ok {
		t.Fatal("expected TEST database in config")
	}
	if db.Driver != "sqlite" {
		t.Errorf("want driver sqlite, got %s", db.Driver)
	}
	if db.DSN != "/tmp/test.db" {
		t.Errorf("want DSN /tmp/test.db, got %s", db.DSN)
	}
}

func TestValidate_Valid(t *testing.T) {
	cfg := Load()
	if err := cfg.Validate(); err != nil {
		t.Errorf("expected valid config, got %v", err)
	}
}

func TestValidate_InvalidPort(t *testing.T) {
	cfg := &Config{Port: "99999"}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for invalid port")
	}
}

func TestValidate_EmptyDSN(t *testing.T) {
	cfg := &Config{
		Port: "8530",
		Databases: map[string]DBConfig{
			"BAD": {Name: "BAD", Driver: "postgres", DSN: ""},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for empty DSN")
	}
}
