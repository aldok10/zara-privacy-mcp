package db

import (
	"testing"
)

// ─── Driver Resolution Tests ───────────────────────────────────────────────

func TestResolveDriver(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		want     string
		wantOK   bool
	}{
		{"postgres canonical", "postgres", "postgres", true},
		{"pg alias", "pg", "postgres", true},
		{"postgresql alias", "postgresql", "postgres", true},
		{"mysql canonical", "mysql", "mysql", true},
		{"mariadb alias", "mariadb", "mysql", true},
		{"maria alias", "maria", "mysql", true},
		{"sqlite canonical", "sqlite", "sqlite", true},
		{"sqlite3 alias", "sqlite3", "sqlite", true},
		{"sqlserver canonical", "sqlserver", "sqlserver", true},
		{"mssql alias", "mssql", "sqlserver", true},
		{"microsoft alias", "microsoft", "sqlserver", true},
		{"uppercase MYSQL", "MYSQL", "mysql", true},
		{"mixed case MariaDB", "MariaDB", "mysql", true},
		{"oracle canonical", "oracle", "oracle", true},
		{"ora alias", "ora", "oracle", true},
		{"clickhouse canonical", "clickhouse", "clickhouse", true},
		{"ch alias", "ch", "clickhouse", true},
		{"unknown driver", "cockroachdb", "", false},
		{"empty string", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ResolveDriver(tt.input)
			if got != tt.want || ok != tt.wantOK {
				t.Errorf("ResolveDriver(%q) = (%q, %v), want (%q, %v)", tt.input, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

// ─── DSN Auto-Detection Tests ──────────────────────────────────────────────

func TestDetectDriverFromDSN(t *testing.T) {
	tests := []struct {
		name string
		dsn  string
		want string
	}{
		// PostgreSQL
		{"postgres full URL", "postgres://user:pass@localhost:5432/db", "postgres"},
		{"postgres with params", "postgres://user:pass@localhost:5432/db?sslmode=disable", "postgres"},
		{"postgresql URL", "postgresql://user:pass@localhost:5432/db", "postgres"},

		// MySQL
		{"mysql full URL", "mysql://user:pass@localhost:3306/db", "mysql"},
		{"mariadb URL", "mariadb://user:pass@localhost:3306/db", "mysql"},
		{"mysql tcp DSN", "user:pass@tcp(localhost:3306)/db", "mysql"},
		{"mysql tcp with params", "user:pass@tcp(localhost:3306)/db?charset=utf8", "mysql"},
		{"mysql unix socket", "user:pass@unix(/tmp/mysql.sock)/db", "mysql"},

		// SQL Server
		{"sqlserver full URL", "sqlserver://user:pass@localhost:1433?database=db", "sqlserver"},

		// SQLite
		{"sqlite URL", "sqlite:///path/to/db.sqlite3", "sqlite"},
		{"sqlite .db file", "/path/to/database.db", "sqlite"},
		{"sqlite .sqlite file", "data.sqlite", "sqlite"},

		// Oracle
		{"oracle URL", "oracle://user:pass@localhost:1521/db", "oracle"},

		// ClickHouse
		{"clickhouse URL", "clickhouse://user:pass@localhost:9000/db", "clickhouse"},
		{"clickhouse tcp URL", "tcp://localhost:9000?database=db", "clickhouse"},

		// Unrecognised
		{"empty DSN", "", ""},
		{"unknown DSN", "cockroachdb://localhost:26257/db", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectDriverFromDSN(tt.dsn)
			if got != tt.want {
				t.Errorf("DetectDriverFromDSN(%q) = %q, want %q", tt.dsn, got, tt.want)
			}
		})
	}
}

// ─── Supported Drivers List Tests ───────────────────────────────────────────

func TestSupportedDrivers(t *testing.T) {
	drivers := SupportedDrivers()

	if len(drivers) < 6 {
		t.Errorf("Expected at least 6 supported drivers, got %d: %v", len(drivers), drivers)
	}

	// Verify all core drivers are present
	required := []string{"postgres", "mysql", "sqlite", "sqlserver", "oracle", "clickhouse"}
	for _, r := range required {
		found := false
		for _, d := range drivers {
			if d == r {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Required driver %q not found in SupportedDrivers(): %v", r, drivers)
		}
	}
}

// ─── Driver Map Consistency Test ───────────────────────────────────────────

func TestDriverMapAllAliasesResolve(t *testing.T) {
	// Every alias should resolve back to the canonical driver name
	for _, d := range supportedDrivers {
		for _, alias := range d.Aliases {
			got, ok := ResolveDriver(alias)
			if !ok {
				t.Errorf("Alias %q did not resolve for driver %q", alias, d.DriverName)
			}
			if got != d.DriverName {
				t.Errorf("Alias %q resolved to %q, expected %q", alias, got, d.DriverName)
			}
		}
	}
}

// ─── DSN-Priority Test (regression) ─────────────────────────────────────────
//
// Postgres DSNs should not be misidentified as MySQL.
func TestDetectDSNNoConflict(t *testing.T) {
	tests := []struct {
		name string
		dsns []string
		want string
	}{
		{
			"postgres not mysql",
			[]string{
				"postgres://user:pass@localhost:5432/db",
				"postgresql://user:pass@localhost:5432/db",
			},
			"postgres",
		},
		{
			"sqlite not postgres",
			[]string{
				"sqlite:///tmp/test.db",
				"/tmp/test.db",
			},
			"sqlite",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, dsn := range tt.dsns {
				got := DetectDriverFromDSN(dsn)
				if got != tt.want {
					t.Errorf("DSN %q detected as %q, want %q", dsn, got, tt.want)
				}
			}
		})
	}
}
