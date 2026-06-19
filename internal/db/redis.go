// Package db provides secure database access with automatic data masking.
package db

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aldok10/zara-privacy-mcp/internal/detector"
	"github.com/redis/go-redis/v9"
)

// RedisConfig for a Redis connection.
type RedisConfig struct {
	Name            string
	Addr            string // host:port
	Username        string
	Password        string
	DB              int
	PoolSize        int           // max connections in pool (default: 10)
	MinIdleConns    int           // min idle connections kept open (default: 2)
	ConnMaxIdleTime time.Duration // close idle connections after this (default: 5m)
	Timeout         time.Duration // optional, default 10s
}

// RedisDB wraps a single Redis connection with masking.
type RedisDB struct {
	Config    RedisConfig
	client    *redis.Client
	secretDet *detector.SecretDetector
	piiDet    *detector.PIIDetector
}

// RedisRegistry manages multiple Redis connections.
type RedisRegistry struct {
	mu    sync.RWMutex
	conns map[string]*RedisDB
}

// RedisResult holds the result of a Redis operation.
type RedisResult struct {
	Command   string        `json:"command"`
	Result    interface{}   `json:"result"`
	Duration  string        `json:"duration"`
	Masked    []MaskedField `json:"masked,omitempty"`
}

// NewRedisRegistry creates an empty Redis registry.
func NewRedisRegistry() *RedisRegistry {
	return &RedisRegistry{
		conns: make(map[string]*RedisDB),
	}
}

// Add creates and registers a new Redis connection.
func (r *RedisRegistry) Add(cfg RedisConfig, secretDet *detector.SecretDetector, piiDet *detector.PIIDetector) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.conns[cfg.Name]; exists {
		return fmt.Errorf("redis %q already registered", cfg.Name)
	}

	// Pool best-practice defaults
	poolSize := cfg.PoolSize
	if poolSize <= 0 {
		poolSize = 10
	}
	minIdle := cfg.MinIdleConns
	if minIdle <= 0 {
		minIdle = 2
	}
	maxIdleTime := cfg.ConnMaxIdleTime
	if maxIdleTime <= 0 {
		maxIdleTime = 5 * time.Minute
	}

	client := redis.NewClient(&redis.Options{
		Addr:            cfg.Addr,
		Username:        cfg.Username,
		Password:        cfg.Password,
		DB:              cfg.DB,
		PoolSize:        poolSize,
		MinIdleConns:    minIdle,
		ConnMaxIdleTime: maxIdleTime,
	})

	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("redis ping %s: %w", cfg.Name, err)
	}

	r.conns[cfg.Name] = &RedisDB{
		Config:    cfg,
		client:    client,
		secretDet: secretDet,
		piiDet:    piiDet,
	}
	return nil
}

// Get returns a registered Redis by name.
func (r *RedisRegistry) Get(name string) (*RedisDB, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	db, ok := r.conns[name]
	return db, ok
}

// List returns names of all registered Redis instances.
func (r *RedisRegistry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.conns))
	for n := range r.conns {
		names = append(names, n)
	}
	return names
}

// CloseAll closes all Redis connections.
func (r *RedisRegistry) CloseAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, rd := range r.conns {
		rd.client.Close()
	}
}

// ─── Commands ───────────────────────────────────────────────────────────────

// Do executes an arbitrary Redis command and returns the result with masking.
func (r *RedisDB) Do(command string, args ...interface{}) (*RedisResult, error) {
	start := time.Now()

	ctx := context.Background()
	cmd := r.client.Do(ctx, append([]interface{}{command}, args...)...)
	if err := cmd.Err(); err != nil {
		return nil, fmt.Errorf("redis %s: %w", command, err)
	}

	val := cmd.Val()
	maskedResult, masked := r.maskResult(val, command)

	return &RedisResult{
		Command:  command,
		Result:   maskedResult,
		Duration: time.Since(start).Round(time.Microsecond).String(),
		Masked:   masked,
	}, nil
}

// Keys returns all keys matching a pattern.
func (r *RedisDB) Keys(pattern string) ([]string, error) {
	ctx := context.Background()
	return r.client.Keys(ctx, pattern).Result()
}

// ─── Masking ────────────────────────────────────────────────────────────────

// maskResult recursively scans redis values for secrets/PII.
func (r *RedisDB) maskResult(val interface{}, command string) (interface{}, []MaskedField) {
	switch v := val.(type) {
	case string:
		if v == "" {
			return v, nil
		}
		secrets := r.secretDet.Scan(v)
		pii := r.piiDet.ScanWithContext(v)
		if len(secrets) == 0 && len(pii) == 0 {
			return v, nil
		}
		var masked []MaskedField
		maskedVal := v
		for _, s := range secrets {
			maskedVal = strings.Replace(maskedVal, s.Value, detector.MaskSecret(s.Value), 1)
			masked = append(masked, MaskedField{
				Column: command,
				Row:    0,
				Type:   s.Type,
				Risk:   int(s.Risk),
			})
		}
		for _, p := range pii {
			maskedVal = strings.Replace(maskedVal, p.Value, detector.MaskSecret(p.Value), 1)
			masked = append(masked, MaskedField{
				Column: command,
				Row:    0,
				Type:   p.Type,
				Risk:   int(p.Risk),
			})
		}
		return maskedVal, masked

	case []interface{}:
		var allMasked []MaskedField
		result := make([]interface{}, len(v))
		for i, item := range v {
			maskedItem, m := r.maskResult(item, command)
			result[i] = maskedItem
			allMasked = append(allMasked, m...)
		}
		return result, allMasked

	case map[interface{}]interface{}:
		var allMasked []MaskedField
		result := make(map[string]interface{})
		for k, item := range v {
			keyStr := fmt.Sprintf("%v", k)
			maskedItem, m := r.maskResult(item, command+"."+keyStr)
			result[keyStr] = maskedItem
			allMasked = append(allMasked, m...)
		}
		return result, allMasked

	default:
		return v, nil
	}
}
