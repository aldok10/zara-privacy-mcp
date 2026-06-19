// Package config centralizes all configuration for the Zara Privacy MCP server.
package config

import (
	"os"
	"strconv"
)

// Config holds all configuration for the MCP server.
type Config struct {
	// Server
	Port           string
	Host           string
	LogLevel       string

	// MCP
	ServerName     string
	ServerVersion  string

	// Encryption
	EncryptionKey  string

	// Storage
	DBPath         string
	DBType         string // "sqlite" or "postgres"

	// Scanning
	DefaultLocales []string
	MaxContextSize int // in bytes

	// Compression
	MaxTokens      int
	CompressEnable bool

	// Metrics
	MetricsEnable  bool
	MetricsPort    string
}

// Load reads configuration from environment variables with sensible defaults.
func Load() *Config {
	return &Config{
		Port:           getEnv("ZARA_MCP_PORT", "8530"),
		Host:           getEnv("ZARA_MCP_HOST", "127.0.0.1"),
		LogLevel:       getEnv("ZARA_LOG_LEVEL", "info"),

		ServerName:     getEnv("ZARA_MCP_NAME", "zara-privacy-mcp"),
		ServerVersion:  getEnv("ZARA_MCP_VERSION", "0.1.0"),

		EncryptionKey:  getEnv("ZARA_ENCRYPTION_KEY", ""),
		DBPath:         getEnv("ZARA_DB_PATH", "~/.zara/privacymcp/mappings.db"),
		DBType:         getEnv("ZARA_DB_TYPE", "sqlite"),

		DefaultLocales: []string{"id", "sg", "global"},
		MaxContextSize: getEnvInt("ZARA_MAX_CONTEXT_BYTES", 1024*1024), // 1MB

		MaxTokens:      getEnvInt("ZARA_MAX_TOKENS", 4096),
		CompressEnable: getEnvBool("ZARA_COMPRESS_ENABLED", true),

		MetricsEnable:  getEnvBool("ZARA_METRICS_ENABLED", true),
		MetricsPort:    getEnv("ZARA_METRICS_PORT", "8531"),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return fallback
}
