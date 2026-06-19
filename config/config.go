// Package config centralizes all configuration for the Zara Secure MCP Gateway.
package config

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// ─── Core Config ────────────────────────────────────────────────────────────

// Config holds all configuration for the MCP server.
type Config struct {
	// Transport: "http" or "stdio"
	Transport string

	// Server
	Port     string
	Host     string
	LogLevel string

	// MCP
	ServerName    string
	ServerVersion string

	// Encryption
	EncryptionKey string

	// Storage (mapping store)
	DBPath string

	// Scanning
	DefaultLocales []string
	MaxContextSize int

	// Compression
	MaxTokens      int
	CompressEnable bool

	// Metrics
	MetricsEnable bool
	MetricsPort   string

	// OpenObserve
	ObserveEnable bool
	ObserveURL    string
	ObserveUser   string
	ObserveKey    string
	ObserveStream string

	// Hot-reload
	ReloadSignal bool // enable SIGHUP reload

	// External connections (parsed from env)
	Databases   map[string]DBConfig
	MongoDBs    map[string]MongoDBConfig
	RedisDBs    map[string]RedisDBConfig
	APIs        map[string]APIConfig
	AIProviders map[string]AIProviderConfig
}

// ─── Database Config ────────────────────────────────────────────────────────

// DBConfig represents a database connection (SQL).
type DBConfig struct {
	Name            string
	Driver          string // "postgres", "mysql", "sqlite", "sqlserver", "oracle", "clickhouse"
	DSN             string
	MaxConns        int // max open connections (0 = default 10)
	MaxIdleConns    int // max idle connections (0 = default half of MaxConns)
	ConnMaxLifetime int // seconds, max conn lifetime (0 = default 1800s/30m)
	ConnMaxIdleTime int // seconds, max idle time (0 = default 300s/5m)
}

// MongoDBConfig represents a MongoDB connection.
type MongoDBConfig struct {
	Name     string
	URI      string
	Database string
}

// RedisDBConfig represents a Redis connection.
type RedisDBConfig struct {
	Name            string
	Addr            string
	Username        string
	Password        string
	DB              int
	PoolSize        int // max pool connections (0 = default 10)
	MinIdleConns    int // min idle connections (0 = default 2)
	ConnMaxIdleTime int // seconds (0 = default 300s/5m)
}

// ─── HTTP API Config ────────────────────────────────────────────────────────

// APIConfig represents an external API endpoint.
type APIConfig struct {
	Name     string
	BaseURL  string
	AuthType string // "none", "bearer", "basic", "header"
	AuthEnv  string // env var name for token/password
	Headers  map[string]string
}

// ─── AI Provider Config ─────────────────────────────────────────────────────

// AIProviderConfig represents an AI/LLM provider.
type AIProviderConfig struct {
	Name    string
	BaseURL string
	APIKey  string   // primary key (first resolved)
	APIKeys []string // all keys (for pool round-robin)
	Models  []string
}

// ─── Load ───────────────────────────────────────────────────────────────────

// Load reads configuration from environment variables with sensible defaults.
func Load() *Config {
	c := &Config{
		Transport: getEnv("ZARA_MCP_TRANSPORT", "http"),
		Port:      getEnv("ZARA_MCP_PORT", "8530"),
		Host:      getEnv("ZARA_MCP_HOST", "127.0.0.1"),
		LogLevel:  getEnv("ZARA_LOG_LEVEL", "info"),

		ServerName:    getEnv("ZARA_MCP_NAME", "zara-privacy-mcp"),
		ServerVersion: getEnv("ZARA_MCP_VERSION", "0.2.0"),

		EncryptionKey: getEnv("ZARA_ENCRYPTION_KEY", ""),
		DBPath:        getEnv("ZARA_DB_PATH", "~/.zara/privacymcp/mappings.db"),

		DefaultLocales: []string{"id", "sg", "global"},
		MaxContextSize: getEnvInt("ZARA_MAX_CONTEXT_BYTES", 1024*1024),

		MaxTokens:      getEnvInt("ZARA_MAX_TOKENS", 4096),
		CompressEnable: getEnvBool("ZARA_COMPRESS_ENABLED", true),

		MetricsEnable: getEnvBool("ZARA_METRICS_ENABLED", true),
		MetricsPort:   getEnv("ZARA_METRICS_PORT", "8531"),

		ObserveEnable: getEnvBool("ZARA_OBSERVE_ENABLED", false),
		ObserveURL:    getEnv("ZARA_OBSERVE_URL", ""),
		ObserveUser:   getEnv("ZARA_OBSERVE_USER", ""),
		ObserveKey:    getEnv("ZARA_OBSERVE_KEY", ""),
		ObserveStream: getEnv("ZARA_OBSERVE_STREAM", "zara-mcp"),

		ReloadSignal: getEnvBool("ZARA_RELOAD_ENABLED", true),

		Databases:   make(map[string]DBConfig),
		MongoDBs:    make(map[string]MongoDBConfig),
		RedisDBs:    make(map[string]RedisDBConfig),
		APIs:        make(map[string]APIConfig),
		AIProviders: make(map[string]AIProviderConfig),
	}

	c.parseDatabases()
	c.parseMongoDBs()
	c.parseRedisDBs()
	c.parseAPIs()
	c.parseAIProviders()

	return c
}

// ─── Database Config Parsing ────────────────────────────────────────────────
//
// Format:
//   ZARA_DB_<NAME>_DRIVER=postgres|mysql|sqlite|sqlserver|oracle|clickhouse
//   ZARA_DB_<NAME>_DSN=postgres://user:pass@host:5432/db
//   ZARA_DB_<NAME>_MAX_CONNS=10 (optional, default 10)
//   ZARA_DB_<NAME>_MAX_IDLE_CONNS=5 (optional, default half of MAX_CONNS)
//   ZARA_DB_<NAME>_CONN_MAX_LIFETIME=1800 (optional, seconds, default 30m)
//   ZARA_DB_<NAME>_CONN_MAX_IDLE_TIME=300 (optional, seconds, default 5m)

func (c *Config) parseDatabases() {
	prefix := "ZARA_DB_"
	suffixes := []string{"_DRIVER", "_DSN", "_MAX_CONNS", "_MAX_IDLE_CONNS", "_CONN_MAX_LIFETIME", "_CONN_MAX_IDLE_TIME"}

	names := c.collectNames(prefix, suffixes)
	for _, name := range names {
		driver := getEnv(prefix+name+"_DRIVER", "postgres")
		dsn := getEnv(prefix+name+"_DSN", "")

		if dsn == "" {
			continue
		}

		c.Databases[name] = DBConfig{
			Name:            name,
			Driver:          driver,
			DSN:             dsn,
			MaxConns:        getEnvInt(prefix+name+"_MAX_CONNS", 0),
			MaxIdleConns:    getEnvInt(prefix+name+"_MAX_IDLE_CONNS", 0),
			ConnMaxLifetime: getEnvInt(prefix+name+"_CONN_MAX_LIFETIME", 0),
			ConnMaxIdleTime: getEnvInt(prefix+name+"_CONN_MAX_IDLE_TIME", 0),
		}
	}
}

// ─── MongoDB Config Parsing ─────────────────────────────────────────────────
//
// Format:
//   ZARA_MONGO_<NAME>_URI=mongodb://user:pass@host:27017
//   ZARA_MONGO_<NAME>_DATABASE=mydb

func (c *Config) parseMongoDBs() {
	prefix := "ZARA_MONGO_"
	suffixes := []string{"_URI", "_DATABASE"}

	names := c.collectNames(prefix, suffixes)
	for _, name := range names {
		uri := getEnv(prefix+name+"_URI", "")
		database := getEnv(prefix+name+"_DATABASE", "")

		if uri == "" || database == "" {
			continue
		}

		c.MongoDBs[name] = MongoDBConfig{
			Name:     name,
			URI:      uri,
			Database: database,
		}
	}
}

// ─── Redis Config Parsing ───────────────────────────────────────────────────
//
// Format:
//   ZARA_REDIS_<NAME>_ADDR=localhost:6379
//   ZARA_REDIS_<NAME>_USERNAME=optional
//   ZARA_REDIS_<NAME>_PASSWORD=optional
//   ZARA_REDIS_<NAME>_DB=0 (optional, default 0)
//   ZARA_REDIS_<NAME>_POOL_SIZE=10 (optional, default 10)
//   ZARA_REDIS_<NAME>_MIN_IDLE_CONNS=2 (optional, default 2)
//   ZARA_REDIS_<NAME>_CONN_MAX_IDLE_TIME=300 (optional, seconds, default 5m)

func (c *Config) parseRedisDBs() {
	prefix := "ZARA_REDIS_"
	suffixes := []string{"_ADDR", "_USERNAME", "_PASSWORD", "_DB", "_POOL_SIZE", "_MIN_IDLE_CONNS", "_CONN_MAX_IDLE_TIME"}

	names := c.collectNames(prefix, suffixes)
	for _, name := range names {
		addr := getEnv(prefix+name+"_ADDR", "")
		if addr == "" {
			continue
		}

		c.RedisDBs[name] = RedisDBConfig{
			Name:            name,
			Addr:            addr,
			Username:        getEnv(prefix+name+"_USERNAME", ""),
			Password:        getEnv(prefix+name+"_PASSWORD", ""),
			DB:              getEnvInt(prefix+name+"_DB", 0),
			PoolSize:        getEnvInt(prefix+name+"_POOL_SIZE", 0),
			MinIdleConns:    getEnvInt(prefix+name+"_MIN_IDLE_CONNS", 0),
			ConnMaxIdleTime: getEnvInt(prefix+name+"_CONN_MAX_IDLE_TIME", 0),
		}
	}
}

// ─── HTTP API Config Parsing ────────────────────────────────────────────────
//
// Format:
//   ZARA_API_<NAME>_URL=https://api.example.com
//   ZARA_API_<NAME>_AUTH=bearer|basic|header|none (optional)
//   ZARA_API_<NAME>_AUTH_ENV=GITHUB_TOKEN (env var name for token)
//   ZARA_API_<NAME>_HEADER_<K> = custom header value

func (c *Config) parseAPIs() {
	prefix := "ZARA_API_"
	suffixes := []string{"_URL", "_AUTH", "_AUTH_ENV"}

	names := c.collectNames(prefix, suffixes)
	for _, name := range names {
		baseURL := getEnv(prefix+name+"_URL", "")
		if baseURL == "" {
			continue
		}

		authType := getEnv(prefix+name+"_AUTH", "none")
		authEnv := getEnv(prefix+name+"_AUTH_ENV", "")

		// Collect custom headers: ZARA_API_<NAME>_HEADER_<KEY>
		headers := make(map[string]string)
		headerPrefix := prefix + name + "_HEADER_"
		for _, env := range os.Environ() {
			if !strings.HasPrefix(env, headerPrefix) {
				continue
			}
			parts := strings.SplitN(env, "=", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimPrefix(parts[0], headerPrefix)
			key = strings.ReplaceAll(key, "_", "-")
			headers[key] = parts[1]
		}

		c.APIs[name] = APIConfig{
			Name:     name,
			BaseURL:  strings.TrimRight(baseURL, "/"),
			AuthType: authType,
			AuthEnv:  authEnv,
			Headers:  headers,
		}
	}
}

// ─── AI Provider Config Parsing ─────────────────────────────────────────────
//
// Format:
//   ZARA_AI_<NAME>_BASE_URL=https://api.openai.com
//   ZARA_AI_<NAME>_API_KEY_ENV=OPENAI_API_KEY (env var containing the key)
//   ZARA_AI_<NAME>_MODELS=gpt-4o,gpt-4o-mini (comma-separated)

func (c *Config) parseAIProviders() {
	prefix := "ZARA_AI_"
	suffixes := []string{"_BASE_URL", "_API_KEY_ENV", "_MODELS"}

	names := c.collectNames(prefix, suffixes)
	for _, name := range names {
		baseURL := getEnv(prefix+name+"_BASE_URL", "")
		if baseURL == "" {
			continue
		}

		apiKeyEnv := getEnv(prefix+name+"_API_KEY_ENV", "")

		// Support comma-separated env var names for multi-key pools
		var apiKeys []string
		for _, envName := range strings.Split(apiKeyEnv, ",") {
			envName = strings.TrimSpace(envName)
			if envName == "" {
				continue
			}
			if key := os.Getenv(envName); key != "" {
				apiKeys = append(apiKeys, key)
			}
		}

		var primaryKey string
		if len(apiKeys) > 0 {
			primaryKey = apiKeys[0]
		}

		modelsStr := getEnv(prefix+name+"_MODELS", "")
		var models []string
		if modelsStr != "" {
			for _, m := range strings.Split(modelsStr, ",") {
				m = strings.TrimSpace(m)
				if m != "" {
					models = append(models, m)
				}
			}
		}

		c.AIProviders[name] = AIProviderConfig{
			Name:    name,
			BaseURL: strings.TrimRight(baseURL, "/"),
			APIKey:  primaryKey,
			APIKeys: apiKeys,
			Models:  models,
		}
	}
}

// ─── Helper: collect config names ──────────────────────────────────────────
//
// Scans environment for variables matching prefix + * + any suffix,
// extracts the name segment.

func (c *Config) collectNames(prefix string, suffixes []string) []string {
	set := make(map[string]bool)

	for _, env := range os.Environ() {
		if !strings.HasPrefix(env, prefix) {
			continue
		}
		rest := strings.TrimPrefix(env, prefix)
		for _, suffix := range suffixes {
			if idx := strings.Index(rest, suffix); idx > 0 {
				name := rest[:idx]
				if name != "" {
					set[name] = true
				}
			}
		}
	}

	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// ─── Summary ────────────────────────────────────────────────────────────────

// Summary returns a human-readable summary of all configured connections.
func (c *Config) Summary() string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("Zara Secure MCP v%s\n", c.ServerVersion))
	b.WriteString(fmt.Sprintf("Transport: %s\n", c.Transport))

	b.WriteString(fmt.Sprintf("\nSQL Databases (%d):\n", len(c.Databases)))
	for _, db := range c.Databases {
		b.WriteString(fmt.Sprintf("  ─ %s (%s)\n", db.Name, db.Driver))
	}

	b.WriteString(fmt.Sprintf("\nMongoDB (%d):\n", len(c.MongoDBs)))
	for _, m := range c.MongoDBs {
		b.WriteString(fmt.Sprintf("  ─ %s → %s/%s\n", m.Name, m.URI, m.Database))
	}

	b.WriteString(fmt.Sprintf("\nRedis (%d):\n", len(c.RedisDBs)))
	for _, r := range c.RedisDBs {
		b.WriteString(fmt.Sprintf("  ─ %s → %s\n", r.Name, r.Addr))
	}

	b.WriteString(fmt.Sprintf("\nHTTP APIs (%d):\n", len(c.APIs)))
	for _, api := range c.APIs {
		b.WriteString(fmt.Sprintf("  ─ %s → %s\n", api.Name, api.BaseURL))
	}

	b.WriteString(fmt.Sprintf("\nAI Providers (%d):\n", len(c.AIProviders)))
	for _, ai := range c.AIProviders {
		b.WriteString(fmt.Sprintf("  ─ %s (%d models)\n", ai.Name, len(ai.Models)))
	}

	return b.String()
}

// ─── Low-level helpers ──────────────────────────────────────────────────────

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

// ─── Validation ─────────────────────────────────────────────────────────────

// Validate checks configuration for common errors.
// Returns nil if valid, error describing the problem otherwise.
func (c *Config) Validate() error {
	if c.Port != "" {
		p, err := strconv.Atoi(c.Port)
		if err != nil || p < 1 || p > 65535 {
			return fmt.Errorf("invalid port: %s", c.Port)
		}
	}
	for name, db := range c.Databases {
		if db.DSN == "" {
			return fmt.Errorf("database %s: DSN is empty", name)
		}
	}
	for name, m := range c.MongoDBs {
		if m.URI == "" {
			return fmt.Errorf("mongodb %s: URI is empty", name)
		}
		if m.Database == "" {
			return fmt.Errorf("mongodb %s: database name is empty", name)
		}
	}
	for name, r := range c.RedisDBs {
		if r.Addr == "" {
			return fmt.Errorf("redis %s: address is empty", name)
		}
	}
	for name, a := range c.APIs {
		if a.BaseURL == "" {
			return fmt.Errorf("api %s: URL is empty", name)
		}
	}
	for name, ai := range c.AIProviders {
		if ai.BaseURL == "" {
			return fmt.Errorf("ai provider %s: base URL is empty", name)
		}
	}
	return nil
}
