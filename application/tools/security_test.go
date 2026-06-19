package tools

import "testing"

func TestValidateSQL(t *testing.T) {
	tests := []struct {
		name    string
		query   string
		wantErr bool
	}{
		{"block DROP TABLE", "DROP TABLE users", true},
		{"block TRUNCATE", "TRUNCATE TABLE logs", true},
		{"block ALTER", "ALTER TABLE users ADD col int", true},
		{"block CREATE", "CREATE TABLE foo (id int)", true},
		{"block GRANT", "GRANT ALL ON db TO user", true},
		{"block REVOKE", "REVOKE ALL ON db FROM user", true},
		{"block LOAD_FILE", "SELECT LOAD_FILE('/etc/passwd')", true},
		{"block INTO OUTFILE", "SELECT * INTO OUTFILE '/tmp/x' FROM users", true},
		{"block XP_CMDSHELL", "EXEC XP_CMDSHELL 'dir'", true},
		{"block COPY PROGRAM", "COPY PROGRAM '/bin/sh'", true},
		{"block multi-statement", "SELECT 1; DROP TABLE users;", true},
		{"block DELETE without WHERE", "DELETE FROM users", true},
		{"block UPDATE without WHERE", "UPDATE users SET active=0", true},
		{"allow SELECT with WHERE", "SELECT * FROM users WHERE id = 1", false},
		{"allow INSERT INTO", "INSERT INTO users (name) VALUES ('test')", false},
		{"allow DELETE with WHERE", "DELETE FROM users WHERE id = 1", false},
		{"allow UPDATE with WHERE", "UPDATE users SET name='x' WHERE id = 1", false},
		{"allow CTE", "WITH active AS (SELECT * FROM users WHERE active=1) SELECT * FROM active", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSQL(tt.query)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateSQL(%q) error = %v, wantErr %v", tt.query, err, tt.wantErr)
			}
		})
	}
}

func TestValidateRedisCommand(t *testing.T) {
	tests := []struct {
		name    string
		command string
		wantErr bool
	}{
		{"block FLUSHALL", "FLUSHALL", true},
		{"block FLUSHDB", "FLUSHDB", true},
		{"block SHUTDOWN", "SHUTDOWN", true},
		{"block CONFIG", "CONFIG", true},
		{"block DEBUG", "DEBUG", true},
		{"block EVAL", "EVAL", true},
		{"block EVALSHA", "EVALSHA", true},
		{"block SCRIPT", "SCRIPT", true},
		{"block SLAVEOF", "SLAVEOF", true},
		{"block REPLICAOF", "REPLICAOF", true},
		{"block MODULE", "MODULE", true},
		{"block CLUSTER", "CLUSTER", true},
		{"allow GET", "GET", false},
		{"allow SET", "SET", false},
		{"allow HGETALL", "HGETALL", false},
		{"allow LPUSH", "LPUSH", false},
		{"allow RPUSH", "RPUSH", false},
		{"allow DEL", "DEL", false},
		{"allow KEYS", "KEYS", false},
		{"allow SCAN", "SCAN", false},
		{"allow EXPIRE", "EXPIRE", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRedisCommand(tt.command)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateRedisCommand(%q) error = %v, wantErr %v", tt.command, err, tt.wantErr)
			}
		})
	}
}

func TestValidateMongoFilter(t *testing.T) {
	tests := []struct {
		name    string
		filter  map[string]any
		wantErr bool
	}{
		{"block $where", map[string]any{"$where": "this.a > 1"}, true},
		{"block $expr", map[string]any{"$expr": map[string]any{"$gt": []any{"$a", 1}}}, true},
		{"block $function", map[string]any{"$function": "return true"}, true},
		{"block $accumulator", map[string]any{"$accumulator": "sum"}, true},
		{"block nested $where", map[string]any{"field": map[string]any{"$where": "1==1"}}, true},
		{"allow simple filter", map[string]any{"name": "test"}, false},
		{"allow $gt", map[string]any{"age": map[string]any{"$gt": 18}}, false},
		{"allow $and", map[string]any{"$and": []any{"a", "b"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateMongoFilter(tt.filter)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateMongoFilter(%v) error = %v, wantErr %v", tt.filter, err, tt.wantErr)
			}
		})
	}
}
