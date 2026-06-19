// Package version holds build-time version info injected via ldflags.
package version

// Set via -ldflags at build time.
var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// String returns a formatted version string.
func String() string {
	return Version + " (" + Commit + ") built " + Date
}
