package storage

import "strings"

// IsPostgresDSN reports whether the string looks like a postgres connection string.
func IsPostgresDSN(value string) bool {
	trimmed := strings.TrimSpace(strings.ToLower(value))
	return strings.HasPrefix(trimmed, "postgres://") || strings.HasPrefix(trimmed, "postgresql://")
}
