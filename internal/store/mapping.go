// Package store manages encrypted placeholder mappings and state persistence.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"maps"
	"strings"
	"sync"
	"time"

	"github.com/aldok10/zara-privacy-mcp/internal/crypto"
	"github.com/aldok10/zara-privacy-mcp/internal/detector"
	_ "modernc.org/sqlite"
)

// MappingStore manages placeholder-to-original mappings with encrypted persistence.
type MappingStore struct {
	db       *sql.DB
	enc      *crypto.Encryptor
	mu       sync.RWMutex
	inMemory map[string]detector.Mapping
	counter  map[string]int
}

// NewMappingStore creates a new store backed by SQLite.
// dbPath is the path to the SQLite database file.
// encKey is the encryption key for encrypting stored mappings.
func NewMappingStore(dbPath string, encKey []byte) (*MappingStore, error) {
	db, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL&_secure_delete=true&_txlock=immediate")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}

	s := &MappingStore{
		db:       db,
		enc:      crypto.NewEncryptor(encKey),
		inMemory: make(map[string]detector.Mapping),
		counter:  make(map[string]int),
	}

	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}

	// Load existing mappings into memory
	s.loadFromDB()

	return s, nil
}

func (s *MappingStore) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS mappings (
			placeholder TEXT PRIMARY KEY,
			original_encrypted TEXT NOT NULL,
			type TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			accessed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_mappings_type ON mappings(type);
		CREATE INDEX IF NOT EXISTS idx_mappings_accessed ON mappings(accessed_at);
	`)
	return err
}

func (s *MappingStore) loadFromDB() {
	rows, err := s.db.Query("SELECT placeholder, original_encrypted, type FROM mappings")
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var placeholder, encrypted, mtype string
		if err := rows.Scan(&placeholder, &encrypted, &mtype); err != nil {
			continue
		}

		original, err := s.enc.DecryptString(encrypted)
		if err != nil {
			continue
		}

		s.inMemory[placeholder] = detector.Mapping{
			Placeholder: placeholder,
			Original:    original,
			Type:        mtype,
		}
	}
}

// GetOrCreate returns an existing placeholder for a value, or creates a new one.
func (s *MappingStore) GetOrCreate(original string, mtype string) detector.Mapping {
	s.mu.Lock()

	// Check if already mapped
	for _, m := range s.inMemory {
		if m.Original == original {
			s.mu.Unlock()
			return m
		}
	}

	// Create new mapping
	s.counter[mtype]++
	label := placeholderLabel(mtype)
	placeholder := fmt.Sprintf("[%s_%d]", label, s.counter[mtype])

	mapping := detector.Mapping{
		Placeholder: placeholder,
		Original:    original,
		Type:        mtype,
	}
	s.inMemory[placeholder] = mapping
	s.mu.Unlock()

	// Persist outside lock — SQLite handles its own concurrency
	s.persistMapping(mapping)

	return mapping
}

// Lookup finds the original value for a placeholder.
func (s *MappingStore) Lookup(placeholder string) (detector.Mapping, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m, ok := s.inMemory[placeholder]
	return m, ok
}

// GetAll returns all current mappings (for restoration/serialization).
func (s *MappingStore) GetAll() []detector.Mapping {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]detector.Mapping, 0, len(s.inMemory))
	for _, m := range s.inMemory {
		result = append(result, m)
	}
	return result
}

// Stats returns statistics about the store.
func (s *MappingStore) Stats() map[string]int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := map[string]int{
		"total_mappings": len(s.inMemory),
	}
	for _, m := range s.inMemory {
		stats["type_"+m.Type]++
	}
	return stats
}

// Snapshot returns an encrypted JSON snapshot of all mappings for backup.
func (s *MappingStore) Snapshot() (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := json.Marshal(s.inMemory)
	if err != nil {
		return "", err
	}

	return s.enc.Encrypt(data)
}

// RestoreFromSnapshot restores mappings from an encrypted snapshot.
func (s *MappingStore) RestoreFromSnapshot(encrypted string) error {
	data, err := s.enc.Decrypt(encrypted)
	if err != nil {
		return err
	}

	var mappings map[string]detector.Mapping
	if err := json.Unmarshal(data, &mappings); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	maps.Copy(s.inMemory, mappings)

	return nil
}

func (s *MappingStore) persistMapping(m detector.Mapping) {
	encrypted, err := s.enc.EncryptString(m.Original)
	if err != nil {
		log.Printf("[WARN] persistMapping encrypt: %v", err)
		return
	}

	if _, err := s.db.Exec(
		"INSERT OR REPLACE INTO mappings (placeholder, original_encrypted, type, accessed_at) VALUES (?, ?, ?, ?)",
		m.Placeholder, encrypted, m.Type, time.Now().UTC(),
	); err != nil {
		log.Printf("[WARN] persistMapping write: %v", err)
	}
}

// Close closes the database connection.
func (s *MappingStore) Close() error {
	return s.db.Close()
}

// placeholderLabel returns a readable label for a detection type.
func placeholderLabel(mtype string) string {
	switch {
	case strings.Contains(mtype, "Email"):
		return "EMAIL"
	case strings.Contains(mtype, "Phone"):
		return "PHONE"
	case strings.Contains(mtype, "Credit Card"):
		return "CC"
	case strings.Contains(mtype, "KTP") || strings.Contains(mtype, "NIK"):
		return "NIK"
	case strings.Contains(mtype, "NPWP"):
		return "NPWP"
	case strings.Contains(mtype, "Passport"):
		return "PASSPORT"
	case strings.Contains(mtype, "NRIC"):
		return "NRIC"
	case strings.Contains(mtype, "API Key"):
		return "API_KEY"
	case strings.Contains(mtype, "JWT"):
		return "JWT"
	case strings.Contains(mtype, "Token"):
		return "TOKEN"
	case strings.Contains(mtype, "Key"):
		return "KEY"
	case strings.Contains(mtype, "Private Key"):
		return "PKEY"
	case strings.Contains(mtype, "URL"):
		return "URL"
	case strings.Contains(mtype, "Database"):
		return "DB"
	case strings.Contains(mtype, "IP"):
		return "IP"
	default:
		return "REDACTED"
	}
}
