// Package db provides secure database access with automatic data masking.
// Supports PostgreSQL, MySQL, MariaDB, SQL Server, and SQLite.
// All query results pass through the privacy engine before being returned to the agent.
package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aldok10/zara-privacy-mcp/internal/detector"
	"github.com/aldok10/zara-privacy-mcp/internal/masking"

	// Register database/sql drivers
	_ "github.com/ClickHouse/clickhouse-go/v2"
	_ "github.com/denisenkom/go-mssqldb"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "github.com/sijms/go-ora/v2"
	_ "modernc.org/sqlite"
)

// Registry manages multiple database connections.
type Registry struct {
	mu    sync.RWMutex
	conns map[string]*DB
}

// DB wraps a single database connection with masking.
type DB struct {
	Config    Config
	db        *sql.DB
	masker    *masking.Masker
	secretDet *detector.SecretDetector
	piiDet    *detector.PIIDetector
}

// Config for a database connection.
type Config struct {
	Name            string
	Driver          string // "postgres", "mysql", "sqlite", "sqlserver", "oracle", "clickhouse"
	DSN             string
	MaxConns        int           // max open connections (default: 10)
	MaxIdleConns    int           // max idle connections (default: 5)
	ConnMaxLifetime time.Duration // max connection lifetime (default: 30m)
	ConnMaxIdleTime time.Duration // max idle time before close (default: 5m)
}

// DriverInfo holds metadata about a supported driver.
type DriverInfo struct {
	// DriverName is the Go database/sql driver name to register.
	DriverName string
	// Aliases are alternative names users can specify in config.
	Aliases []string
	// DetectDSN returns true if the DSN matches this driver's format.
	DetectDSN func(dsn string) bool
}

// supportedDrivers lists all available database drivers.
var supportedDrivers = []DriverInfo{
	{
		DriverName: "postgres",
		Aliases:    []string{"pg", "postgresql"},
		DetectDSN: func(dsn string) bool {
			return strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://")
		},
	},
	{
		DriverName: "mysql",
		Aliases:    []string{"mariadb", "maria", "mysql"},
		DetectDSN: func(dsn string) bool {
			return strings.HasPrefix(dsn, "mysql://") ||
				strings.HasPrefix(dsn, "mariadb://") ||
				// user:password@tcp(host:port)/dbname or @unix(/path) — no protocol prefix
				(strings.Contains(dsn, "@") && (strings.Contains(dsn, "@tcp(") || strings.Contains(dsn, "@unix(")))
		},
	},
	{
		DriverName: "sqlserver",
		Aliases:    []string{"mssql", "microsoft", "azuresql"},
		DetectDSN:  func(dsn string) bool { return strings.HasPrefix(dsn, "sqlserver://") },
	},
	{
		DriverName: "sqlite",
		Aliases:    []string{"sqlite3", "sqlite"},
		DetectDSN: func(dsn string) bool {
			if strings.HasPrefix(dsn, "sqlite://") {
				return true
			}
			if !strings.Contains(dsn, "://") {
				lower := strings.ToLower(dsn)
				if strings.HasSuffix(lower, ".db") || strings.HasSuffix(lower, ".sqlite") || strings.HasSuffix(lower, ".sqlite3") {
					return true
				}
			}
			return false
		},
	},
	{
		DriverName: "oracle",
		Aliases:    []string{"oracle", "ora", "oci"},
		DetectDSN:  func(dsn string) bool { return strings.HasPrefix(dsn, "oracle://") || strings.HasPrefix(dsn, "oracle:") },
	},
	{
		DriverName: "clickhouse",
		Aliases:    []string{"clickhouse", "ch"},
		DetectDSN: func(dsn string) bool {
			return strings.HasPrefix(dsn, "clickhouse://") || strings.HasPrefix(dsn, "tcp://")
		},
	},
}

// driverMap caches driver name → DriverInfo lookup.
var driverMap = sync.OnceValue(func() map[string]DriverInfo {
	m := make(map[string]DriverInfo)
	for _, d := range supportedDrivers {
		m[d.DriverName] = d
		for _, alias := range d.Aliases {
			m[alias] = d
		}
	}
	return m
})

// ResolveDriver resolves a user-provided driver string to the canonical name.
// Returns the canonical driver name and whether it was found.
func ResolveDriver(driver string) (string, bool) {
	if d, ok := driverMap()[strings.ToLower(driver)]; ok {
		return d.DriverName, true
	}
	return "", false
}

// DetectDriverFromDSN attempts to detect the driver from the DSN string.
// Returns the canonical driver name, or empty string if detection fails.
func DetectDriverFromDSN(dsn string) string {
	dsn = strings.TrimSpace(dsn)
	if dsn == "" {
		return ""
	}

	for _, d := range supportedDrivers {
		if d.DetectDSN(dsn) {
			return d.DriverName
		}
	}
	return ""
}

// SupportedDrivers returns a human-readable list of supported drivers.
func SupportedDrivers() []string {
	seen := make(map[string]bool)
	var list []string
	for _, d := range supportedDrivers {
		if !seen[d.DriverName] {
			list = append(list, d.DriverName)
			seen[d.DriverName] = true
		}
	}
	return list
}

// QueryResult holds the result of a query with optional masking metadata.
type QueryResult struct {
	Columns      []string         `json:"columns"`
	Rows         []map[string]any `json:"rows"`
	RowsAffected int64            `json:"rows_affected,omitempty"`
	Duration     string           `json:"duration"`
	Masked       []MaskedField    `json:"masked,omitempty"`
}

// MaskedField describes a field that was masked in the result.
type MaskedField struct {
	Column string `json:"column"`
	Row    int    `json:"row"`
	Type   string `json:"type"`
	Risk   int    `json:"risk"`
}

// ColumnInfo describes a table column.
type ColumnInfo struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Nullable string `json:"nullable"`
	Key      string `json:"key,omitempty"`
	Default  string `json:"default,omitempty"`
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry {
	return &Registry{
		conns: make(map[string]*DB),
	}
}

// Add creates and registers a new database connection.
func (r *Registry) Add(cfg Config, secretDet *detector.SecretDetector, piiDet *detector.PIIDetector) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.conns[cfg.Name]; exists {
		return fmt.Errorf("database %q already registered", cfg.Name)
	}

	db, err := r.open(cfg)
	if err != nil {
		return fmt.Errorf("open %s: %w", cfg.Name, err)
	}

	r.conns[cfg.Name] = &DB{
		Config:    cfg,
		db:        db,
		masker:    masking.New(secretDet, piiDet),
		secretDet: secretDet,
		piiDet:    piiDet,
	}
	return nil
}

// Get returns a registered database by name.
func (r *Registry) Get(name string) (*DB, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	db, ok := r.conns[name]
	return db, ok
}

// List returns names of all registered databases.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.conns))
	for n := range r.conns {
		names = append(names, n)
	}
	return names
}

// CloseAll closes all database connections.
func (r *Registry) CloseAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, db := range r.conns {
		db.db.Close()
	}
}

func (r *Registry) open(cfg Config) (*sql.DB, error) {
	// Resolve driver: normalize alias → canonical name
	driverName, ok := ResolveDriver(cfg.Driver)
	if !ok {
		// Try auto-detection from DSN
		detected := DetectDriverFromDSN(cfg.DSN)
		if detected != "" {
			driverName = detected
		} else {
			return nil, fmt.Errorf("unsupported driver: %q — supported: %v", cfg.Driver, SupportedDrivers())
		}
	}

	db, err := sql.Open(driverName, cfg.DSN)
	if err != nil {
		return nil, err
	}

	// Connection pool best-practice defaults
	maxOpen := cfg.MaxConns
	if maxOpen <= 0 {
		maxOpen = 10
	}
	maxIdle := cfg.MaxIdleConns
	if maxIdle <= 0 {
		maxIdle = max(maxOpen/2, 2)
	}
	connMaxLifetime := cfg.ConnMaxLifetime
	if connMaxLifetime <= 0 {
		connMaxLifetime = 30 * time.Minute
	}
	connMaxIdleTime := cfg.ConnMaxIdleTime
	if connMaxIdleTime <= 0 {
		connMaxIdleTime = 5 * time.Minute
	}

	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(maxIdle)
	db.SetConnMaxLifetime(connMaxLifetime)
	db.SetConnMaxIdleTime(connMaxIdleTime)

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}

	return db, nil
}

// driverDialect returns the SQL dialect name for driver-specific queries.
func (d *DB) driverDialect() string {
	driver := d.Config.Driver
	switch {
	case driver == "postgres" || driver == "pg" || driver == "postgresql":
		return "postgres"
	case driver == "mysql" || driver == "mariadb" || driver == "maria":
		return "mysql"
	case driver == "sqlserver" || driver == "mssql" || driver == "azuresql":
		return "sqlserver"
	case driver == "sqlite" || driver == "sqlite3":
		return "sqlite"
	case driver == "oracle" || driver == "ora" || driver == "oci":
		return "oracle"
	case driver == "clickhouse" || driver == "ch":
		return "clickhouse"
	default:
		return "postgres" // safest fallback (information_schema is standard)
	}
}

// placeholders returns SQL parameter placeholders for the driver's dialect.
// postgres: $1, $2  |  mysql/sqlite/clickhouse: ?, ?  |  sqlserver: @p1, @p2  |  oracle: :1, :2
func (d *DB) placeholders(args []any) string {
	if len(args) == 0 {
		return ""
	}

	dialect := d.driverDialect()
	var phs []string
	for i := range args {
		switch dialect {
		case "postgres":
			phs = append(phs, fmt.Sprintf("$%d", i+1))
		case "sqlserver":
			phs = append(phs, fmt.Sprintf("@p%d", i+1))
		case "oracle":
			phs = append(phs, fmt.Sprintf(":%d", i+1))
		default: // mysql, sqlite, clickhouse
			phs = append(phs, "?")
		}
	}
	return strings.Join(phs, ", ")
}

// ─── Query Execution ────────────────────────────────────────────────────────

// Query runs a SELECT query and returns masked results.
func (d *DB) Query(query string, args ...any) (*QueryResult, error) {
	start := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	rows, err := d.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("columns: %w", err)
	}

	var result []map[string]any
	var masked []MaskedField
	rowIdx := 0

	for rows.Next() {
		values := make([]any, len(columns))
		valuePtrs := make([]any, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}

		row := make(map[string]any)
		for i, col := range columns {
			val := values[i]
			if b, ok := val.([]byte); ok {
				val = string(b)
			}

			// Mask sensitive values in this cell
			strVal, isStr := val.(string)
			if isStr && strVal != "" {
				maskedVal, found := d.maskValue(strVal, col, rowIdx)
				row[col] = maskedVal
				for _, m := range found {
					masked = append(masked, m)
				}
			} else {
				row[col] = val
			}
		}
		result = append(result, row)
		rowIdx++
	}

	if result == nil {
		result = []map[string]any{} // empty, not null
	}

	return &QueryResult{
		Columns:  columns,
		Rows:     result,
		Duration: time.Since(start).Round(time.Microsecond).String(),
		Masked:   masked,
	}, nil
}

// Exec runs a non-SELECT query (INSERT, UPDATE, DELETE).
func (d *DB) Exec(query string, args ...any) (*QueryResult, error) {
	start := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := d.db.ExecContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("exec: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()

	return &QueryResult{
		Columns:      []string{},
		Rows:         []map[string]any{},
		RowsAffected: rowsAffected,
		Duration:     time.Since(start).Round(time.Microsecond).String(),
	}, nil
}

// ─── Schema Inspection ──────────────────────────────────────────────────────

// ListTables returns all table names in the database.
func (d *DB) ListTables() ([]string, error) {
	var query string
	switch d.driverDialect() {
	case "postgres":
		query = `SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name`
	case "mysql":
		query = `SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE() ORDER BY table_name`
	case "sqlserver":
		query = `SELECT table_name FROM information_schema.tables WHERE table_type = 'BASE TABLE' ORDER BY table_name`
	case "sqlite":
		query = `SELECT name FROM sqlite_master WHERE type='table' ORDER BY name`
	case "oracle":
		query = `SELECT table_name FROM user_tables ORDER BY table_name`
	case "clickhouse":
		query = `SELECT name FROM system.tables WHERE database = currentDatabase() ORDER BY name`
	default:
		query = `SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name`
	}

	rows, err := d.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			continue
		}
		tables = append(tables, name)
	}
	return tables, nil
}

// DescribeTable returns column information for a table.
func (d *DB) DescribeTable(table string) ([]ColumnInfo, error) {
	safeName := sanitizeName(table)

	switch d.driverDialect() {
	case "postgres":
		return d.describePostgres(safeName)
	case "mysql":
		return d.describeMySQL(safeName)
	case "sqlserver":
		return d.describeSQLServer(safeName)
	case "sqlite":
		return d.describeSQLite(safeName)
	case "oracle":
		return d.describeOracle(safeName)
	case "clickhouse":
		return d.describeClickHouse(safeName)
	default:
		return d.describePostgres(safeName)
	}
}

func (d *DB) describePostgres(table string) ([]ColumnInfo, error) {
	query := fmt.Sprintf(`
		SELECT column_name, data_type, is_nullable,
			COALESCE(character_maximum_length::text, '') AS max_len,
			COALESCE(column_default, '') AS col_default
		FROM information_schema.columns
		WHERE table_name = '%s'
		ORDER BY ordinal_position`, table)

	rows, err := d.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cols []ColumnInfo
	for rows.Next() {
		var ci ColumnInfo
		var maxLen, defaultVal string
		if err := rows.Scan(&ci.Name, &ci.Type, &ci.Nullable, &maxLen, &defaultVal); err != nil {
			continue
		}
		if maxLen != "" {
			ci.Type = fmt.Sprintf("%s(%s)", ci.Type, maxLen)
		}
		ci.Default = defaultVal
		cols = append(cols, ci)
	}
	return cols, nil
}

func (d *DB) describeMySQL(table string) ([]ColumnInfo, error) {
	query := fmt.Sprintf(`
		SELECT column_name, column_type, is_nullable,
			COALESCE(column_default, '') AS col_default,
			COALESCE(column_key, '') AS col_key
		FROM information_schema.columns
		WHERE table_schema = DATABASE() AND table_name = '%s'
		ORDER BY ordinal_position`, table)

	rows, err := d.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cols []ColumnInfo
	for rows.Next() {
		var ci ColumnInfo
		var key string
		if err := rows.Scan(&ci.Name, &ci.Type, &ci.Nullable, &ci.Default, &key); err != nil {
			continue
		}
		if key != "" {
			ci.Key = key
		}
		cols = append(cols, ci)
	}
	return cols, nil
}

func (d *DB) describeSQLServer(table string) ([]ColumnInfo, error) {
	query := fmt.Sprintf(`
		SELECT column_name, data_type, is_nullable,
			COALESCE(character_maximum_length::varchar, '') AS max_len,
			COALESCE(column_default, '') AS col_default
		FROM information_schema.columns
		WHERE table_name = '%s'
		ORDER BY ordinal_position`, table)

	rows, err := d.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cols []ColumnInfo
	for rows.Next() {
		var ci ColumnInfo
		var maxLen, defaultVal string
		if err := rows.Scan(&ci.Name, &ci.Type, &ci.Nullable, &maxLen, &defaultVal); err != nil {
			continue
		}
		if maxLen != "" {
			ci.Type = fmt.Sprintf("%s(%s)", ci.Type, maxLen)
		}
		ci.Default = defaultVal
		cols = append(cols, ci)
	}
	return cols, nil
}

func (d *DB) describeSQLite(table string) ([]ColumnInfo, error) {
	query := fmt.Sprintf(`PRAGMA table_info('%s')`, table)
	rows, err := d.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cols []ColumnInfo
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull int
		var dflt sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			continue
		}
		nullable := "YES"
		if notnull == 1 {
			nullable = "NO"
		}
		ci := ColumnInfo{
			Name:     name,
			Type:     ctype,
			Nullable: nullable,
		}
		if dflt.Valid {
			ci.Default = dflt.String
		}
		if pk == 1 {
			ci.Key = "PRI"
		}
		cols = append(cols, ci)
	}
	return cols, nil
}

func (d *DB) describeOracle(table string) ([]ColumnInfo, error) {
	query := fmt.Sprintf(`
		SELECT column_name, data_type, nullable,
			COALESCE(data_default, '') AS col_default
		FROM user_tab_columns
		WHERE table_name = '%s'
		ORDER BY column_id`, table)

	rows, err := d.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cols []ColumnInfo
	for rows.Next() {
		var ci ColumnInfo
		var nullable string // "Y" or "N"
		if err := rows.Scan(&ci.Name, &ci.Type, &nullable, &ci.Default); err != nil {
			continue
		}
		if nullable == "Y" {
			ci.Nullable = "YES"
		} else {
			ci.Nullable = "NO"
		}
		cols = append(cols, ci)
	}
	return cols, nil
}

func (d *DB) describeClickHouse(table string) ([]ColumnInfo, error) {
	query := fmt.Sprintf(`
		SELECT name, type, is_nullable,
			COALESCE(default_expression, '') AS col_default
		FROM system.columns
		WHERE database = currentDatabase() AND table = '%s'
		ORDER BY position`, table)

	rows, err := d.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cols []ColumnInfo
	for rows.Next() {
		var ci ColumnInfo
		var nullable uint8
		if err := rows.Scan(&ci.Name, &ci.Type, &nullable, &ci.Default); err != nil {
			continue
		}
		ci.Nullable = "NO"
		if nullable == 1 {
			ci.Nullable = "YES"
		}
		cols = append(cols, ci)
	}
	return cols, nil
}

// ─── Masking ────────────────────────────────────────────────────────────────

// maskValue checks a single cell value for secrets/PII and masks if found.
func (d *DB) maskValue(val, column string, rowIdx int) (any, []MaskedField) {
	masked, findings := d.masker.MaskString(val)
	if len(findings) == 0 {
		return val, nil
	}

	var fields []MaskedField
	for _, f := range findings {
		fields = append(fields, MaskedField{
			Column: column,
			Row:    rowIdx,
			Type:   f.Type,
			Risk:   int(f.Risk),
		})
	}
	return masked, fields
}

// sanitizeName safely quotes a table/column name.
func sanitizeName(name string) string {
	var safe strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			safe.WriteRune(r)
		}
	}
	return safe.String()
}
