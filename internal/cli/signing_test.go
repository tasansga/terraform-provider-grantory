package cli

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tasansga/terraform-provider-grantory/internal/config"
	"github.com/tasansga/terraform-provider-grantory/internal/server"
	"github.com/tasansga/terraform-provider-grantory/internal/storage"
)

func TestCLISigning(t *testing.T) {
	t.Parallel()

	// 1. Setup server with RequireSignatures: true
	dataDir := t.TempDir()

	// We need to use a random port, but srv.Serve() doesn't easily expose it if we use Listen(":0").
	// We'll use a fixed but hopefully free port for simplicity in this integration test.
	port := 58080
	serverURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	cfg := config.Config{
		Database:          dataDir,
		RequireSignatures: true,
		BindAddr:          fmt.Sprintf("127.0.0.1:%d", port),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := server.New(ctx, cfg)
	require.NoError(t, err)
	defer func() { _ = srv.Close() }()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ctx)
	}()

	// Wait for server to start
	time.Sleep(200 * time.Millisecond)

	// 2. Generate key pair and register host
	// Use DefaultNamespace ("_def") explicitly to match CLI and Server default
	store, err := storage.New(ctx, server.NamespaceDBPath(dataDir, server.DefaultNamespace))
	require.NoError(t, err)
	defer func() { _ = store.Close() }()
	require.NoError(t, store.Migrate(ctx))

	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	pubHex := hex.EncodeToString(pub)
	privHex := hex.EncodeToString(priv)

	host, err := store.CreateHost(ctx, storage.Host{
		PublicKey: pubHex,
		UniqueKey: "signed-host",
	})
	require.NoError(t, err)

	// 3. Write private key to file
	keyFile := filepath.Join(t.TempDir(), "key.hex")
	require.NoError(t, os.WriteFile(keyFile, []byte(privHex), 0600))

	// 4. Test success with --private-key-file
	reqPayloadFile := filepath.Join(t.TempDir(), "request.json")
	require.NoError(t, os.WriteFile(reqPayloadFile, []byte(`{"data":"test"}`), 0644))

	cmd := NewRootCommand()
	cmd.SetArgs([]string{
		"--backend", "api",
		"--server-url", serverURL,
		"--private-key-file", keyFile,
		"create", "requests",
		"--host-id", host.ID,
		"--payload-file", reqPayloadFile,
	})

	err = cmd.Execute()
	assert.NoError(t, err, "CLI should succeed with valid signature")

	// 5. Test failure without --private-key-file
	cmdNoKey := NewRootCommand()
	cmdNoKey.SetArgs([]string{
		"--backend", "api",
		"--server-url", serverURL,
		"create", "requests",
		"--host-id", host.ID,
		"--payload-file", reqPayloadFile,
	})

	err = cmdNoKey.Execute()
	assert.Error(t, err, "CLI should fail without required signature")
	assert.Contains(t, err.Error(), "401", "expected 401 Unauthorized error")
}
