package tools

import (
	"testing"
)

// FuzzValidateSQL tests SQL injection detection against adversarial inputs.
func FuzzValidateSQL(f *testing.F) {
	// Seed corpus: known injection patterns
	seeds := []string{
		"SELECT * FROM users",
		"SELECT 1; DROP TABLE users",
		"SELECT * FROM users WHERE id = 1 UNION SELECT password FROM admin",
		"SELECT * FROM users WHERE name = '' OR 1=1--",
		"SELECT * FROM users WHERE id = 1; EXEC xp_cmdshell('dir')",
		"SELECT * FROM users WHERE id = SLEEP(5)",
		"SELECT * FROM users WHERE id = BENCHMARK(1000000, SHA1('test'))",
		"SELECT * FROM t WHERE x='a'/**/UNION/**/SELECT/**/1,2,3--",
		"SELECT CHAR(83)+CHAR(65) FROM dual",
		"SELECT * FROM users WAITFOR DELAY '0:0:5'",
		"SELECT * FROM users WHERE id = PG_SLEEP(5)",
		"'; DROP TABLE users; --",
		"1 UNION ALL SELECT NULL,NULL,table_name FROM information_schema.tables--",
		"SELECT * FROM users INTO OUTFILE '/tmp/dump'",
		"GRANT ALL ON *.* TO 'hacker'@'%'",
		"TRUNCATE TABLE users",
		"ALTER TABLE users DROP COLUMN password",
		// Valid read queries that should pass
		"SELECT id, name FROM users WHERE active = true LIMIT 10",
		"WITH cte AS (SELECT * FROM orders) SELECT * FROM cte",
		"EXPLAIN SELECT * FROM users WHERE id = 1",
		"SHOW TABLES",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, query string) {
		err := validateSQL(query)

		// If it passes validation, verify it's actually safe
		if err == nil {
			// These should NEVER pass
			dangerousPatterns := []string{
				"DROP ", "TRUNCATE ", "ALTER ", "GRANT ",
				"REVOKE ", "INSERT ", "EXEC ", "INTO OUTFILE",
			}
			upper := query
			for i := range upper {
				if upper[i] >= 'a' && upper[i] <= 'z' {
					upper = upper[:i] + string(rune(upper[i]-32)) + upper[i+1:]
				}
			}
			for _, pattern := range dangerousPatterns {
				if contains(upper, pattern) {
					t.Errorf("dangerous query passed validation: %q (contains %q)", query, pattern)
				}
			}
		}
	})
}

func contains(s, substr string) bool {
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
