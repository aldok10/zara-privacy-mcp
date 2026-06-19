package bootstrap

import (
	"os"
	"time"

	"github.com/aldok10/zara-privacy-mcp/config"
)

// ConfigLoader implements runfx.IConfigLoader for the MCP config.
type ConfigLoader struct{}

func (c *ConfigLoader) Load() (config.Config, error) {
	cfg := config.Load()
	if cfg.EncryptionKey == "" {
		cfg.EncryptionKey = "zara-privacy-mcp-default-key-change-me!"
	}
	if len(cfg.EncryptionKey) < 16 {
		os.Exit(1)
	}
	if err := cfg.Validate(); err != nil {
		return config.Config{}, err
	}
	return *cfg, nil
}

func (c *ConfigLoader) StopTimeout() time.Duration {
	return 10 * time.Second
}

func (c *ConfigLoader) DefaultLogLevel() string {
	if v := os.Getenv("ZARA_LOG_LEVEL"); v != "" {
		return v
	}
	return "info"
}
