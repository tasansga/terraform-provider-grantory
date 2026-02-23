package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tasansga/terraform-provider-grantory/internal/storage"
)

func TestStoreFromLocalsVariants(t *testing.T) {
	t.Parallel()

	st, err := storage.New(context.Background(), ":memory:")
	if err != nil {
		assert.NoError(t, err, "New() error")
		return
	}
	defer func() {
		assert.NoError(t, st.Close(), "close store")
	}()

	assert.Equal(t, st, storeFromLocals(st))
	assert.Equal(t, st, storeFromLocals(localStore{store: st}))
	assert.Equal(t, st, storeFromLocals(&localStore{store: st}))
	assert.Nil(t, storeFromLocals("unexpected"))
}
