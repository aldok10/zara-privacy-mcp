package tools

import (
	"fmt"
	"strings"
)

// validateSQL blocks dangerous SQL statements.
func validateSQL(query string) error {
	upper := strings.TrimSpace(strings.ToUpper(query))

	blocked := []string{
		"DROP ", "TRUNCATE ", "ALTER ", "CREATE ",
		"GRANT ", "REVOKE ",
		"LOAD_FILE", "INTO OUTFILE", "INTO DUMPFILE",
		"XP_CMDSHELL", "COPY PROGRAM",
	}
	for _, b := range blocked {
		if strings.Contains(upper, b) {
			return fmt.Errorf("statement contains dangerous keyword %q", strings.TrimSpace(b))
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
	blocked := map[string]bool{
		"FLUSHALL": true, "FLUSHDB": true, "SHUTDOWN": true,
		"CONFIG": true, "DEBUG": true, "EVAL": true, "EVALSHA": true,
		"SCRIPT": true, "SLAVEOF": true, "REPLICAOF": true, "MODULE": true,
		"BGSAVE": true, "BGREWRITEAOF": true, "CLUSTER": true,
	}
	if blocked[strings.ToUpper(command)] {
		return fmt.Errorf("Redis command %q not allowed", command)
	}
	return nil
}

// validateMongoFilter blocks dangerous MongoDB operators.
func validateMongoFilter(filter map[string]interface{}) error {
	blocked := []string{"$where", "$expr", "$function", "$accumulator"}
	for key, val := range filter {
		for _, op := range blocked {
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
