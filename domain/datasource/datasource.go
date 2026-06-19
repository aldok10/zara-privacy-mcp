package datasource

type QueryResult struct {
	Columns  []string                 `json:"columns,omitempty"`
	Rows     []map[string]interface{} `json:"rows"`
	Masked   []MaskedField            `json:"masked,omitempty"`
	Duration string                   `json:"duration,omitempty"`
	Affected int64                    `json:"affected,omitempty"`
}

type MaskedField struct {
	Column string `json:"column"`
	Row    int    `json:"row"`
	Type   string `json:"type"`
	Risk   int    `json:"risk"`
}

type ColumnInfo struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Nullable bool   `json:"nullable"`
	Key      string `json:"key,omitempty"`
	Default  string `json:"default,omitempty"`
}

type SQLDatabase interface {
	Query(query string, params ...interface{}) (*QueryResult, error)
	Exec(query string, params ...interface{}) (*QueryResult, error)
	ListTables() ([]string, error)
	DescribeTable(table string) ([]ColumnInfo, error)
	Close() error
}

type MongoDatabase interface {
	Find(collection string, filter map[string]interface{}, limit int64) (*QueryResult, error)
	ListCollections() ([]string, error)
	Close() error
}

type RedisDatabase interface {
	Do(command string, args ...interface{}) (interface{}, error)
	Keys(pattern string) ([]string, error)
	Close() error
}
