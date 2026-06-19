package datasource

import "fmt"

type Dialect interface {
	ListTablesQuery() string
	DescribeTableQuery(table string) (query string, params []any)
}

type postgresDialect struct{}
type mysqlDialect struct{}
type sqlserverDialect struct{}
type sqliteDialect struct{}
type oracleDialect struct{}
type clickhouseDialect struct{}

func DialectFor(driver string) Dialect {
	switch driver {
	case "postgres", "pg", "postgresql":
		return postgresDialect{}
	case "mysql", "mariadb", "maria":
		return mysqlDialect{}
	case "sqlserver", "mssql", "azuresql":
		return sqlserverDialect{}
	case "sqlite", "sqlite3":
		return sqliteDialect{}
	case "oracle", "ora", "oci":
		return oracleDialect{}
	case "clickhouse", "ch":
		return clickhouseDialect{}
	default:
		return postgresDialect{}
	}
}

func (postgresDialect) ListTablesQuery() string {
	return `SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name`
}

func (postgresDialect) DescribeTableQuery(table string) (string, []any) {
	return `SELECT column_name, data_type, is_nullable,
		COALESCE(character_maximum_length::text, '') AS max_len,
		COALESCE(column_default, '') AS col_default
		FROM information_schema.columns
		WHERE table_name = $1
		ORDER BY ordinal_position`, []any{table}
}

func (mysqlDialect) ListTablesQuery() string {
	return `SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE() ORDER BY table_name`
}

func (mysqlDialect) DescribeTableQuery(table string) (string, []any) {
	return `SELECT column_name, column_type, is_nullable,
		COALESCE(column_default, '') AS col_default,
		COALESCE(column_key, '') AS col_key
		FROM information_schema.columns
		WHERE table_schema = DATABASE() AND table_name = ?
		ORDER BY ordinal_position`, []any{table}
}

func (sqlserverDialect) ListTablesQuery() string {
	return `SELECT table_name FROM information_schema.tables WHERE table_type = 'BASE TABLE' ORDER BY table_name`
}

func (sqlserverDialect) DescribeTableQuery(table string) (string, []any) {
	return fmt.Sprintf(`SELECT column_name, data_type, is_nullable,
		COALESCE(CAST(character_maximum_length AS varchar), '') AS max_len,
		COALESCE(column_default, '') AS col_default
		FROM information_schema.columns
		WHERE table_name = @p1
		ORDER BY ordinal_position`), []any{table}
}

func (sqliteDialect) ListTablesQuery() string {
	return `SELECT name FROM sqlite_master WHERE type='table' ORDER BY name`
}

func (sqliteDialect) DescribeTableQuery(table string) (string, []any) {
	return `SELECT * FROM pragma_table_info(?)`, []any{table}
}

func (oracleDialect) ListTablesQuery() string {
	return `SELECT table_name FROM user_tables ORDER BY table_name`
}

func (oracleDialect) DescribeTableQuery(table string) (string, []any) {
	return `SELECT column_name, data_type, nullable,
		COALESCE(data_default, '') AS col_default
		FROM user_tab_columns
		WHERE table_name = :1
		ORDER BY column_id`, []any{table}
}

func (clickhouseDialect) ListTablesQuery() string {
	return `SELECT name FROM system.tables WHERE database = currentDatabase() ORDER BY name`
}

func (clickhouseDialect) DescribeTableQuery(table string) (string, []any) {
	return `SELECT name, type, is_nullable,
		COALESCE(default_expression, '') AS col_default
		FROM system.columns
		WHERE database = currentDatabase() AND table = ?
		ORDER BY position`, []any{table}
}
