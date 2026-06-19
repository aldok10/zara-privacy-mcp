package tools

import (
	"fmt"
	"regexp"
	"strings"
)

// Package-level blocklists — allocated once, not per-call.
var (
	blockedSQLKeywords = []string{
		"DROP ", "TRUNCATE ", "ALTER ", "CREATE ",
		"GRANT ", "REVOKE ",
		"LOAD_FILE", "INTO OUTFILE", "INTO DUMPFILE",
		"XP_CMDSHELL", "COPY PROGRAM",
		"INSERT ", "REPLACE ",
		"EXEC ", "EXECUTE ",
		"CALL ",
		"RENAME ",
	}

	// Patterns that indicate injection attempts even in SELECT queries.
	blockedSQLPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i);\s*(DROP|ALTER|CREATE|TRUNCATE|INSERT|UPDATE|DELETE|EXEC|GRANT|REVOKE)`),
		regexp.MustCompile(`(?i)UNION\s+(ALL\s+)?SELECT`),
		regexp.MustCompile(`(?i)INTO\s+(OUTFILE|DUMPFILE)`),
		regexp.MustCompile(`(?i)/\*.*\*/`), // block SQL comments used to obfuscate
		regexp.MustCompile(`(?i)--\s*$`),   // trailing line comment (common injection suffix)
		regexp.MustCompile(`(?i)SLEEP\s*\(`),
		regexp.MustCompile(`(?i)BENCHMARK\s*\(`),
		regexp.MustCompile(`(?i)WAITFOR\s+DELAY`),
		regexp.MustCompile(`(?i)PG_SLEEP\s*\(`),
		regexp.MustCompile(`(?i)CHAR\s*\(\s*\d+`), // CHAR() used to bypass string filters
	}

	blockedRedisCommands = map[string]bool{
		"FLUSHALL": true, "FLUSHDB": true, "SHUTDOWN": true,
		"CONFIG": true, "DEBUG": true, "EVAL": true, "EVALSHA": true,
		"SCRIPT": true, "SLAVEOF": true, "REPLICAOF": true, "MODULE": true,
		"BGSAVE": true, "BGREWRITEAOF": true, "CLUSTER": true,
	}

	blockedMongoOperators = []string{"$where", "$expr", "$function", "$accumulator"}
)

// validateSQL blocks dangerous SQL statements and common injection patterns.
func validateSQL(query string) error {
	// Strip SQL comments that could be used to hide malicious payloads.
	cleaned := stripSQLComments(query)
	upper := strings.TrimSpace(strings.ToUpper(cleaned))

	// Empty query after stripping
	if upper == "" {
		return fmt.Errorf("empty query")
	}

	// Only allow read-only statement prefixes
	if !isReadQuery(upper) {
		// Allow DELETE/UPDATE only with WHERE clause (existing behavior)
		if strings.HasPrefix(upper, "DELETE") || strings.HasPrefix(upper, "UPDATE") {
			if !strings.Contains(upper, "WHERE") {
				return fmt.Errorf("%s without WHERE clause not allowed", strings.Fields(upper)[0])
			}
		} else if strings.HasPrefix(upper, "SET") {
			return fmt.Errorf("SET statements not allowed")
		} else {
			return fmt.Errorf("only read queries (SELECT/WITH/SHOW/EXPLAIN) are allowed; got %q", strings.Fields(upper)[0])
		}
	}

	// Keyword blocklist (catches embedded dangerous keywords even in subqueries)
	for _, kw := range blockedSQLKeywords {
		if strings.Contains(upper, kw) {
			return fmt.Errorf("statement contains dangerous keyword %q", strings.TrimSpace(kw))
		}
	}

	// Pattern-based detection (catches obfuscation, time-based injection, UNION)
	for _, pat := range blockedSQLPatterns {
		if pat.MatchString(query) {
			return fmt.Errorf("query matches blocked pattern: %s", pat.String())
		}
	}

	// Reject multiple statements (semicolons outside string literals)
	if countBareStatements(cleaned) > 1 {
		return fmt.Errorf("multi-statement queries not allowed")
	}

	return nil
}

// stripSQLComments removes -- line comments and /* block comments */ from SQL.
// This prevents attackers from hiding payloads inside comments.
func stripSQLComments(query string) string {
	// Remove block comments
	re := regexp.MustCompile(`/\*[\s\S]*?\*/`)
	query = re.ReplaceAllString(query, " ")
	// Remove line comments
	re2 := regexp.MustCompile(`--[^\n]*`)
	query = re2.ReplaceAllString(query, " ")
	return query
}

// countBareStatements counts semicolons outside of single-quoted string literals.
func countBareStatements(query string) int {
	count := 1
	inString := false
	for i := 0; i < len(query); i++ {
		switch query[i] {
		case '\'':
			if inString && i+1 < len(query) && query[i+1] == '\'' {
				i++ // escaped quote ''
			} else {
				inString = !inString
			}
		case ';':
			if !inString {
				count++
			}
		}
	}
	return count
}

// validateRedisCommand blocks dangerous Redis commands.
func validateRedisCommand(command string) error {
	if blockedRedisCommands[strings.ToUpper(command)] {
		return fmt.Errorf("redis command %q not allowed", command)
	}
	return nil
}

// validateMongoFilter blocks dangerous MongoDB operators recursively.
func validateMongoFilter(filter map[string]any) error {
	for key, val := range filter {
		for _, op := range blockedMongoOperators {
			if strings.EqualFold(key, op) {
				return fmt.Errorf("mongodb operator %q not allowed", key)
			}
		}
		if sub, ok := val.(map[string]any); ok {
			if err := validateMongoFilter(sub); err != nil {
				return err
			}
		}
		if arr, ok := val.([]any); ok {
			for _, elem := range arr {
				if sub, ok := elem.(map[string]any); ok {
					if err := validateMongoFilter(sub); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// isReadQuery returns true if the query is a read-only statement.
func isReadQuery(upper string) bool {
	return strings.HasPrefix(upper, "SELECT") ||
		strings.HasPrefix(upper, "WITH") ||
		strings.HasPrefix(upper, "SHOW") ||
		strings.HasPrefix(upper, "PRAGMA") ||
		strings.HasPrefix(upper, "EXPLAIN") ||
		strings.HasPrefix(upper, "DESCRIBE")
}
