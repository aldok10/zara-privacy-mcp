// Package db provides secure database access with automatic data masking.
package db

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aldok10/zara-privacy-mcp/internal/detector"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// MongoConfig for a MongoDB connection.
type MongoConfig struct {
	Name     string
	URI      string
	Database string
	Timeout  time.Duration // optional, default 30s
}

// MongoDB wraps a single MongoDB connection with masking.
type MongoDB struct {
	Config    MongoConfig
	client    *mongo.Client
	db        *mongo.Database
	secretDet *detector.SecretDetector
	piiDet    *detector.PIIDetector
}

// MongoRegistry manages multiple MongoDB connections.
type MongoRegistry struct {
	mu    sync.RWMutex
	conns map[string]*MongoDB
}

// MongoResult holds the result of a MongoDB operation.
type MongoResult struct {
	Documents  []map[string]interface{} `json:"documents,omitempty"`
	Count      int                      `json:"count,omitempty"`
	Duration   string                   `json:"duration"`
	Collection string                   `json:"collection,omitempty"`
	Masked     []MaskedField            `json:"masked,omitempty"`
}

// NewMongoRegistry creates an empty MongoDB registry.
func NewMongoRegistry() *MongoRegistry {
	return &MongoRegistry{
		conns: make(map[string]*MongoDB),
	}
}

// Add creates and registers a new MongoDB connection.
func (r *MongoRegistry) Add(cfg MongoConfig, secretDet *detector.SecretDetector, piiDet *detector.PIIDetector) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.conns[cfg.Name]; exists {
		return fmt.Errorf("mongodb %q already registered", cfg.Name)
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(cfg.URI))
	if err != nil {
		return fmt.Errorf("mongo connect %s: %w", cfg.Name, err)
	}

	if err := client.Ping(ctx, nil); err != nil {
		client.Disconnect(ctx)
		return fmt.Errorf("mongo ping %s: %w", cfg.Name, err)
	}

	mdb := &MongoDB{
		Config:    cfg,
		client:    client,
		db:        client.Database(cfg.Database),
		secretDet: secretDet,
		piiDet:    piiDet,
	}

	r.conns[cfg.Name] = mdb
	return nil
}

// Get returns a registered MongoDB by name.
func (r *MongoRegistry) Get(name string) (*MongoDB, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	db, ok := r.conns[name]
	return db, ok
}

// List returns names of all registered MongoDBs.
func (r *MongoRegistry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.conns))
	for n := range r.conns {
		names = append(names, n)
	}
	return names
}

// CloseAll closes all MongoDB connections.
func (r *MongoRegistry) CloseAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, m := range r.conns {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		m.client.Disconnect(ctx)
		cancel()
	}
}

// ─── Query Operations ───────────────────────────────────────────────────────

// Find runs a MongoDB find query and returns masked results.
func (m *MongoDB) Find(collection string, filter bson.M, limit int64) (*MongoResult, error) {
	start := time.Now()

	ctx := context.Background()
	opts := options.Find()
	if limit > 0 {
		opts.SetLimit(limit)
	}

	cur, err := m.db.Collection(collection).Find(ctx, filter, opts)
	if err != nil {
		return nil, fmt.Errorf("mongo find: %w", err)
	}
	defer cur.Close(ctx)

	var docs []map[string]interface{}
	var masked []MaskedField
	rowIdx := 0

	for cur.Next(ctx) {
		var doc bson.M
		if err := cur.Decode(&doc); err != nil {
			continue
		}

		flat := make(map[string]interface{})
		m.flattenDoc("", doc, flat, &masked, rowIdx)
		docs = append(docs, flat)
		rowIdx++
	}

	if docs == nil {
		docs = []map[string]interface{}{}
	}

	return &MongoResult{
		Documents:  docs,
		Count:      len(docs),
		Duration:   time.Since(start).Round(time.Microsecond).String(),
		Collection: collection,
		Masked:     masked,
	}, nil
}

// RunCommand executes a raw database command.
func (m *MongoDB) RunCommand(command bson.M) (*MongoResult, error) {
	start := time.Now()

	ctx := context.Background()
	result := m.db.RunCommand(ctx, command)

	var doc bson.M
	if err := result.Decode(&doc); err != nil {
		return nil, fmt.Errorf("mongo command: %w", err)
	}

	flat := make(map[string]interface{})
	var masked []MaskedField
	m.flattenDoc("", doc, flat, &masked, 0)

	return &MongoResult{
		Documents: []map[string]interface{}{flat},
		Count:     1,
		Duration:  time.Since(start).Round(time.Microsecond).String(),
		Masked:    masked,
	}, nil
}

// ListCollections returns all collection names in the database.
func (m *MongoDB) ListCollections() ([]string, error) {
	ctx := context.Background()
	cols, err := m.db.ListCollectionNames(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	if cols == nil {
		cols = []string{}
	}
	return cols, nil
}

// ─── Helpers ────────────────────────────────────────────────────────────────

// flattenDoc flattens a BSON document into a flat map, masking sensitive values.
func (m *MongoDB) flattenDoc(prefix string, doc bson.M, out map[string]interface{}, masked *[]MaskedField, rowIdx int) {
	for key, val := range doc {
		fullKey := key
		if prefix != "" {
			fullKey = prefix + "." + key
		}

		switch v := val.(type) {
		case bson.M:
			m.flattenDoc(fullKey, v, out, masked, rowIdx)
		case []interface{}:
			out[fullKey] = fmt.Sprintf("%v", v)
		case string:
			if v != "" {
				maskedVal, found := m.maskValue(v, fullKey, rowIdx)
				out[fullKey] = maskedVal
				*masked = append(*masked, found...)
			} else {
				out[fullKey] = v
			}
		default:
			out[fullKey] = v
		}
	}
}

// maskValue checks a string value for secrets/PII and masks if found.
func (m *MongoDB) maskValue(val, field string, rowIdx int) (interface{}, []MaskedField) {
	secrets := m.secretDet.Scan(val)
	pii := m.piiDet.ScanWithContext(val)

	if len(secrets) == 0 && len(pii) == 0 {
		return val, nil
	}

	var masked []MaskedField
	maskedVal := val

	for _, s := range secrets {
		maskedVal = replaceOnce(maskedVal, s.Value, detector.MaskSecret(s.Value))
		masked = append(masked, MaskedField{
			Column: field,
			Row:    rowIdx,
			Type:   s.Type,
			Risk:   int(s.Risk),
		})
	}
	for _, p := range pii {
		maskedVal = replaceOnce(maskedVal, p.Value, detector.MaskSecret(p.Value))
		masked = append(masked, MaskedField{
			Column: field,
			Row:    rowIdx,
			Type:   p.Type,
			Risk:   int(p.Risk),
		})
	}

	return maskedVal, masked
}

// replaceOnce replaces only the first occurrence of old with new.
func replaceOnce(s, old, new string) string {
	if idx := strings.Index(s, old); idx >= 0 {
		return s[:idx] + new + s[idx+len(old):]
	}
	return s
}
