package storage

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPostgresStoreTableQualification(t *testing.T) {
	t.Run("nil receiver returns quoted table name", func(t *testing.T) {
		var s *postgresStore
		assert.Equal(t, `"hosts"`, s.table("hosts"))
		assert.Equal(t, QuoteIdent("schema_definitions"), s.table("schema_definitions"))
	})

	t.Run("empty schema returns quoted table name without empty prefix", func(t *testing.T) {
		s := &postgresStore{schema: ""}
		assert.Equal(t, `"hosts"`, s.table("hosts"))
		assert.NotContains(t, s.table("hosts"), `""."hosts"`)
	})

	t.Run("whitespace-only schema returns quoted table name without empty prefix", func(t *testing.T) {
		s := &postgresStore{schema: "   \t\n  "}
		assert.Equal(t, `"hosts"`, s.table("hosts"))
		assert.NotContains(t, s.table("hosts"), `""."hosts"`)
	})

	t.Run("configured schema returns qualified table name", func(t *testing.T) {
		s := &postgresStore{schema: "custom_schema"}
		assert.Equal(t, `"custom_schema"."hosts"`, s.table("hosts"))
	})

	t.Run("schema updated via SetNamespace", func(t *testing.T) {
		s := &postgresStore{}
		s.SetNamespace("")
		assert.Equal(t, `"requests"`, s.table("requests"))

		s.SetNamespace("tenant_a")
		assert.Equal(t, `"tenant_a"."requests"`, s.table("requests"))

		s.SetNamespace("   ")
		assert.Equal(t, `"requests"`, s.table("requests"))
	})
}
