package tools

import (
	"fmt"
	"strings"
)

// Package-level blocklists — allocated once, not per-call.
var (
	blockedSQLKeywords = []string{
		"DROP ", "TRUNCATE ", "ALTER ", "CREATE ",
		"GRANT ", "REVOKE ",
		"LOAD_FILE", "INTO OUTFILE", "INTO DUMPFILE",
		"XP_CMDSHELL", "COPY PROGRAM",
	}

	blockedRedisCommands = map[string]bool{
		"FLUSHALL": true, "FLUSHDB": true, "SHUTDOWN": true,
		"CONFIG": true, "DEBUG": true, "EVAL": true, "EVALSHA": true,
		"SCRIPT": true, "SLAVEOF": true, "REPLICAOF": true, "MODULE": true,
		"BGSAVE": true, "BGREWRITEAOF": true, "CLUSTER": true,
	}

	blockedMongoOperators = []string{"$where", "$expr", "$function", "$accumulator"}
)

// validateSQL blocks dangerous SQL statements.
func validateSQL(query string) error {
	upper := strings.TrimSpace(strings.ToUpper(query))

	for _, kw := range blockedSQLKeywords {
		if strings.Contains(upper, kw) {
			return fmt.Errorf("statement contains dangerous keyword %q", strings.TrimSpace(kw))
		}
	}

	if strings.Count(query, ";") > 1 {
		return fmt.Errorf("multi-statement queries not allowed")
	}

	if (strings.HasPrefix(upper, "DELETE") || strings.HasPrefix(upper, "UPDATE")) && !strings.Contains(upper, "WHERE") {
		return fmt.Errorf("%s without WHERE clause not allowed", strings.Fields(upper)[0])
	}

	return nil
}

// validateRedisCommand blocks dangerous Redis commands.
func validateRedisCommand(command string) error {
	if blockedRedisCommands[strings.ToUpper(command)] {
		return fmt.Errorf("Redis command %q not allowed", command)
	}
	return nil
}

// validateMongoFilter blocks dangerous MongoDB operators recursively.
func validateMongoFilter(filter map[string]interface{}) error {
	for key, val := range filter {
		for _, op := range blockedMongoOperators {
			if strings.EqualFold(key, op) {
				return fmt.Errorf("MongoDB operator %q not allowed", key)
			}
		}
		if sub, ok := val.(map[string]interface{}); ok {
			if err := validateMongoFilter(sub); err != nil {
				return err
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
