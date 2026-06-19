package privacy

type MappingStore interface {
	GetOrCreate(category, original string) string
	Lookup(placeholder string) (original string, found bool)
	Stats() map[string]interface{}
	Close() error
}
