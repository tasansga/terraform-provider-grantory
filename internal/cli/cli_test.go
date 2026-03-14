package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tasansga/terraform-provider-grantory/internal/server"
	"github.com/tasansga/terraform-provider-grantory/internal/storage"
)

func closeStore(t *testing.T, store storage.Store) {
	t.Helper()
	if err := store.Close(); err != nil {
		t.Errorf("close store: %v", err)
	}
}

func runCLI(t *testing.T, args ...string) string {
	t.Helper()

	cmd := NewRootCommand()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs(args)
	assert.NoError(t, cmd.Execute(), "command should succeed")
	return buf.String()
}

func TestListHostsCommand(t *testing.T) {
	t.Parallel()

	dataDir := prepareTestDataDir(t, func(ctx context.Context, store storage.Store) {
		_, err := store.CreateHost(ctx, storage.Host{
			ID: "cli-host",
		})
		assert.NoError(t, err, "failed to create host for CLI test")
	})

	cmd := NewRootCommand()
	cmd.SetArgs([]string{"--database", dataDir, "list", "hosts"})
	err := cmd.Execute()
	assert.NoError(t, err, "list hosts command failed")
}

func TestMutateHostLabelsCommand(t *testing.T) {
	t.Parallel()

	var hostID string
	dataDir := prepareTestDataDir(t, func(ctx context.Context, store storage.Store) {
		created, err := store.CreateHost(ctx, storage.Host{
			Labels: map[string]string{
				"env": "test",
			},
		})
		assert.NoError(t, err, "failed to create host for labels CLI test")
		hostID = created.ID
	})

	cmd := NewRootCommand()
	cmd.SetArgs([]string{
		"--database", dataDir,
		"mutate", "hosts", hostID,
		"--labels", `{"env":"prod"}`,
	})
	err := cmd.Execute()
	assert.NoError(t, err, "mutate host labels command failed")

	store := openStoreForTesting(t, dataDir)
	defer closeStore(t, store)

	host, err := store.GetHost(context.Background(), hostID)
	assert.NoError(t, err, "GetHost() error")
	assert.Equal(t, "prod", host.Labels["env"], "host env labels after mutate via CLI")
}

func TestMutateHostLabelsFromFile(t *testing.T) {
	t.Parallel()

	var hostID string
	dataDir := prepareTestDataDir(t, func(ctx context.Context, store storage.Store) {
		created, err := store.CreateHost(ctx, storage.Host{
			Labels: map[string]string{
				"env": "initial",
			},
		})
		assert.NoError(t, err, "failed to create host for CLI labels file test")
		hostID = created.ID
	})

	labelsPath := filepath.Join(t.TempDir(), "labels.json")
	assert.NoError(t, os.WriteFile(labelsPath, []byte(`{"env":"file"}`), 0o600), "write labels file failed")

	cmd := NewRootCommand()
	cmd.SetArgs([]string{
		"--database", dataDir,
		"mutate", "hosts", hostID,
		"--labels-file", labelsPath,
	})
	err := cmd.Execute()
	assert.NoError(t, err, "mutate host labels command failed")

	store := openStoreForTesting(t, dataDir)
	defer closeStore(t, store)

	host, err := store.GetHost(context.Background(), hostID)
	assert.NoError(t, err, "GetHost() error")
	assert.Equal(t, "file", host.Labels["env"], "host labels after file input")
}

func TestMutateHostLabelsFromStdin(t *testing.T) {
	t.Parallel()

	var hostID string
	dataDir := prepareTestDataDir(t, func(ctx context.Context, store storage.Store) {
		created, err := store.CreateHost(ctx, storage.Host{
			Labels: map[string]string{
				"env": "start",
			},
		})
		assert.NoError(t, err, "failed to create host for stdin labels CLI test")
		hostID = created.ID
	})

	cmd := NewRootCommand()
	cmd.SetIn(strings.NewReader(`{"env":"stdin"}`))
	cmd.SetArgs([]string{
		"--database", dataDir,
		"mutate", "hosts", hostID,
		"--labels-file", "-",
	})
	err := cmd.Execute()
	assert.NoError(t, err, "mutate host labels command failed")

	store := openStoreForTesting(t, dataDir)
	defer closeStore(t, store)

	host, err := store.GetHost(context.Background(), hostID)
	assert.NoError(t, err, "GetHost() error")
	assert.Equal(t, "stdin", host.Labels["env"], "host labels from stdin")
}

func TestMutateRequestLabelsCommand(t *testing.T) {
	t.Parallel()

	var requestID string
	dataDir := prepareTestDataDir(t, func(ctx context.Context, store storage.Store) {
		host, err := store.CreateHost(ctx, storage.Host{})
		assert.NoError(t, err, "failed to create host for request CLI test")

		created, err := store.CreateRequest(ctx, storage.Request{
			HostID: host.ID,
			Labels: map[string]string{
				"env": "test",
			},
		})
		assert.NoError(t, err, "failed to create request for CLI test")
		requestID = created.ID
	})

	cmd := NewRootCommand()
	cmd.SetArgs([]string{
		"--database", dataDir,
		"mutate", "requests", requestID,
		"--labels", `{"env":"prod"}`,
	})
	err := cmd.Execute()
	assert.NoError(t, err, "mutate request labels command failed")

	store := openStoreForTesting(t, dataDir)
	defer closeStore(t, store)

	req, err := store.GetRequest(context.Background(), requestID)
	assert.NoError(t, err, "GetRequest() error")
	assert.Equal(t, "prod", req.Labels["env"], "request env labels after mutate via CLI")
}

func TestMutateRegisterLabelsCommand(t *testing.T) {
	t.Parallel()

	var registerID string
	dataDir := prepareTestDataDir(t, func(ctx context.Context, store storage.Store) {
		host, err := store.CreateHost(ctx, storage.Host{})
		assert.NoError(t, err, "failed to create host for register CLI test")

		created, err := store.CreateRegister(ctx, storage.Register{
			HostID: host.ID,
			Labels: map[string]string{
				"env": "test",
			},
		})
		assert.NoError(t, err, "failed to create register for CLI test")
		registerID = created.ID
	})

	cmd := NewRootCommand()
	cmd.SetArgs([]string{
		"--database", dataDir,
		"mutate", "registers", registerID,
		"--labels", `{"env":"prod"}`,
	})
	err := cmd.Execute()
	assert.NoError(t, err, "mutate register labels command failed")

	store := openStoreForTesting(t, dataDir)
	defer closeStore(t, store)

	reg, err := store.GetRegister(context.Background(), registerID)
	assert.NoError(t, err, "GetRegister() error")
	assert.Equal(t, "prod", reg.Labels["env"], "register env labels after mutate via CLI")
}

func TestNamespaceFlagTargetsNamespace(t *testing.T) {
	t.Parallel()

	dataDir := prepareTestDataDir(t, nil)

	ctx := context.Background()
	customStore, err := storage.New(ctx, server.NamespaceDBPath(dataDir, "custom-ns"))
	if !assert.NoError(t, err, "storage.New() error") {
		t.FailNow()
	}
	customStore.SetNamespace("custom-ns")
	if !assert.NoError(t, customStore.Migrate(ctx), "Store.Migrate() error") {
		if err := customStore.Close(); err != nil {
			t.Errorf("close custom store: %v", err)
		}
		t.FailNow()
	}
	host := storage.Host{}
	createdHost, err := customStore.CreateHost(ctx, host)
	if !assert.NoError(t, err, "CreateHost() error") {
		if err := customStore.Close(); err != nil {
			t.Errorf("close custom store: %v", err)
		}
		t.FailNow()
	}
	host = createdHost
	if err := customStore.Close(); err != nil {
		t.Errorf("close custom store: %v", err)
	}

	cmd := NewRootCommand()
	cmd.SetArgs([]string{"--database", dataDir, "--namespace", "custom-ns", "delete", "hosts", host.ID})
	assert.NoError(t, cmd.Execute(), "delete host command failed")

	verifyStore, err := storage.New(ctx, server.NamespaceDBPath(dataDir, "custom-ns"))
	if !assert.NoError(t, err, "storage.New() error") {
		t.FailNow()
	}
	verifyStore.SetNamespace("custom-ns")
	defer func() {
		if err := verifyStore.Close(); err != nil {
			t.Errorf("close verify store: %v", err)
		}
	}()

	_, err = verifyStore.GetHost(ctx, host.ID)
	assert.ErrorIs(t, err, storage.ErrHostNotFound, "expected host to be deleted in namespace")
}

func TestListHostsCommandAPIMode(t *testing.T) {
	t.Parallel()

	recorded := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method, "expected GET /hosts")
		assert.Equal(t, "/hosts", r.URL.Path, "unexpected API path")
		recorded <- r.Header.Get("REMOTE_USER")
		w.Header().Set("Content-Type", "application/json")
		assert.NoError(t, json.NewEncoder(w).Encode([]storage.Host{{ID: "api-host"}}), "encode host list")
	}))
	defer srv.Close()

	cmd := NewRootCommand()
	cmd.SetOut(io.Discard)
	cmd.SetArgs([]string{
		"--backend", "api",
		"--server-url", srv.URL,
		"--namespace", "api-ns",
		"list", "hosts",
	})
	assert.NoError(t, cmd.Execute(), "API mode list hosts failed")

	select {
	case got := <-recorded:
		assert.Equal(t, "api-ns", got, "namespace header should be forwarded")
	default:
		t.Fatal("expected namespace header to be recorded")
	}
}

func TestBackendEnvVarHonored(t *testing.T) {

	recorded := make(chan struct {
		namespace string
		auth      string
	}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method, "expected GET /hosts")
		assert.Equal(t, "/hosts", r.URL.Path, "unexpected API path")
		recorded <- struct {
			namespace string
			auth      string
		}{namespace: r.Header.Get("REMOTE_USER"), auth: r.Header.Get("Authorization")}
		w.Header().Set("Content-Type", "application/json")
		assert.NoError(t, json.NewEncoder(w).Encode([]storage.Host{{ID: "env-host"}}), "encode host list")
	}))
	defer server.Close()

	const envTokenValue = "env-token"
	t.Setenv(EnvBackend, string(backendModeAPI))
	t.Setenv(EnvServerURL, server.URL)
	t.Setenv(EnvNamespace, "env-ns")
	t.Setenv(EnvToken, envTokenValue)

	cmd := NewRootCommand()
	cmd.SetOut(io.Discard)
	cmd.SetArgs([]string{"list", "hosts"})
	assert.NoError(t, cmd.Execute(), "env var backend selection failed")

	select {
	case got := <-recorded:
		assert.Equal(t, "env-ns", got.namespace, "namespace header should be forwarded via env var")
		assert.Equal(t, "Bearer "+envTokenValue, got.auth, "expected authorization header")
	default:
		t.Fatal("expected namespace header to be recorded")
	}
}

func TestBackendEnvVarBasicAuth(t *testing.T) {

	recorded := make(chan struct {
		namespace string
		auth      string
	}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method, "expected GET /hosts")
		assert.Equal(t, "/hosts", r.URL.Path, "unexpected API path")
		recorded <- struct {
			namespace string
			auth      string
		}{namespace: r.Header.Get("REMOTE_USER"), auth: r.Header.Get("Authorization")}
		w.Header().Set("Content-Type", "application/json")
		assert.NoError(t, json.NewEncoder(w).Encode([]storage.Host{{ID: "env-host"}}), "encode host list")
	}))
	defer server.Close()

	const envUser = "env-user"
	const envPassword = "top-secret"
	t.Setenv(EnvBackend, string(backendModeAPI))
	t.Setenv(EnvServerURL, server.URL)
	t.Setenv(EnvNamespace, "env-ns")
	t.Setenv(EnvUser, envUser)
	t.Setenv(EnvPassword, envPassword)

	cmd := NewRootCommand()
	cmd.SetOut(io.Discard)
	cmd.SetArgs([]string{"list", "hosts"})
	assert.NoError(t, cmd.Execute(), "env var backend selection failed")

	select {
	case got := <-recorded:
		assert.Equal(t, "env-ns", got.namespace, "namespace header should be forwarded via env var")
		expected := "Basic " + base64.StdEncoding.EncodeToString([]byte(envUser+":"+envPassword))
		assert.Equal(t, expected, got.auth, "expected authorization header")
	default:
		t.Fatal("expected namespace header to be recorded")
	}
}

func TestBackendEnvVarTokenAndUserConflict(t *testing.T) {
	cmd := NewRootCommand()
	cmd.SetArgs([]string{
		"--backend", "api",
		"--server-url", "http://localhost",
		"--token", "tok",
		"--user", "alice",
		"--password", "secret",
		"list", "hosts",
	})
	err := cmd.Execute()
	if assert.Error(t, err, "expected CLI to reject mixed auth") {
		assert.Contains(t, err.Error(), "token/Bearer auth cannot be combined", "expected conflict message")
	}
}

func TestParseResourceTypeUnknown(t *testing.T) {
	t.Parallel()

	_, err := parseResourceType("invalid")
	assert.Error(t, err, "unknown resource types should fail parsing")
}

func TestResolveBackendConfigErrors(t *testing.T) {
	t.Parallel()

	cmd := NewRootCommand()
	if err := cmd.PersistentFlags().Set(FlagBackend, "invalid"); err != nil {
		t.Fatalf("set flag: %v", err)
	}
	_, err := resolveBackendConfig(cmd)
	assert.ErrorContains(t, err, "unknown backend", "should reject unsupported backend values")

	if err := cmd.PersistentFlags().Set(FlagBackend, string(BackendModeAPI)); err != nil {
		t.Fatalf("set flag: %v", err)
	}
	if err := cmd.PersistentFlags().Set(FlagServerURL, ""); err != nil {
		t.Fatalf("set server flag: %v", err)
	}
	_, err = resolveBackendConfig(cmd)
	assert.ErrorContains(t, err, "server URL is required when backend=api")

	if err := cmd.PersistentFlags().Set(FlagToken, ""); err != nil {
		t.Fatalf("reset token: %v", err)
	}
	if err := cmd.PersistentFlags().Set(FlagUser, "alice"); err != nil {
		t.Fatalf("set user: %v", err)
	}
	if err := cmd.PersistentFlags().Set(FlagPassword, ""); err != nil {
		t.Fatalf("clear password: %v", err)
	}
	_, err = resolveBackendConfig(cmd)
	assert.ErrorContains(t, err, "both "+FlagUser+" and "+FlagPassword+" must be provided together")
}

func TestResolveLabelsHelpers(t *testing.T) {
	t.Parallel()

	cmd := NewRootCommand()
	_, err := resolveLabels(cmd, `{"env":`, "")
	assert.ErrorContains(t, err, "parse labels")

	_, err = resolveLabels(cmd, "", "")
	assert.ErrorContains(t, err, "either labels or labels-file must be provided")

	dir := t.TempDir()
	path := filepath.Join(dir, "labels.json")
	assert.NoError(t, os.WriteFile(path, []byte(`{"foo":"bar"}`), 0o600))

	labels, err := loadLabelsFromSource(cmd, path)
	assert.NoError(t, err)
	assert.Equal(t, map[string]string{"foo": "bar"}, labels)

	cmd.SetIn(strings.NewReader(`{"stdin":"value"}`))
	stdinLabels, err := loadLabelsFromSource(cmd, "-")
	assert.NoError(t, err)
	assert.Equal(t, map[string]string{"stdin": "value"}, stdinLabels)

	cmd.SetIn(strings.NewReader(""))
	_, err = loadLabelsFromSource(cmd, "-")
	assert.ErrorContains(t, err, "labels payload is empty")

	_, err = loadLabelsFromSource(cmd, filepath.Join(dir, "missing.json"))
	assert.ErrorContains(t, err, "open labels file")
}

func TestRemoveNamespaceFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	base := filepath.Join(dir, "demo.db")
	for _, suffix := range []string{"", "-wal", "-shm"} {
		assert.NoError(t, os.WriteFile(base+suffix, []byte("x"), 0o600))
	}

	assert.NoError(t, removeNamespaceFiles(base))
	for _, suffix := range []string{"", "-wal", "-shm"} {
		_, err := os.Stat(base + suffix)
		assert.ErrorIs(t, err, os.ErrNotExist)
	}

	assert.NoError(t, removeNamespaceFiles(filepath.Join(t.TempDir(), "missing.db")))
}

func TestResolveNamespaceInvalid(t *testing.T) {

	cmd := NewRootCommand()
	t.Setenv(EnvNamespace, "Invalid Namespace")
	_, err := resolveNamespace(cmd)
	assert.Error(t, err, "invalid namespace values should be rejected")
}

func TestInspectHostsCommand(t *testing.T) {
	t.Parallel()

	var hostID string
	dataDir := prepareTestDataDir(t, func(ctx context.Context, store storage.Store) {
		host, err := store.CreateHost(ctx, storage.Host{})
		assert.NoError(t, err, "create host failed")
		hostID = host.ID
	})

	cmd := NewRootCommand()
	cmd.SetOut(io.Discard)
	cmd.SetArgs([]string{"--database", dataDir, "inspect", "hosts", hostID})
	assert.NoError(t, cmd.Execute(), "inspect hosts command should succeed")
}

func TestInspectRequestWithoutGrant(t *testing.T) {
	t.Parallel()

	var requestID string
	dataDir := prepareTestDataDir(t, func(ctx context.Context, store storage.Store) {
		host, err := store.CreateHost(ctx, storage.Host{})
		assert.NoError(t, err, "create host failed")
		req, err := store.CreateRequest(ctx, storage.Request{HostID: host.ID})
		assert.NoError(t, err, "create request failed")
		requestID = req.ID
	})

	output := runCLI(t, "--database", dataDir, "inspect", "requests", requestID)

	var response map[string]any
	assert.NoError(t, json.Unmarshal([]byte(output), &response))
	assert.Equal(t, false, response["has_grant"], "has_grant should be false")
	_, hasGrantID := response["grant_id"]
	assert.False(t, hasGrantID, "grant_id should be absent without grant")
	_, hasGrantPayload := response["grant_payload"]
	assert.False(t, hasGrantPayload, "grant_payload should be absent without grant")
}

func TestInspectRequestWithGrant(t *testing.T) {
	t.Parallel()

	var requestID string
	var grantID string
	dataDir := prepareTestDataDir(t, func(ctx context.Context, store storage.Store) {
		host, err := store.CreateHost(ctx, storage.Host{})
		assert.NoError(t, err, "create host failed")
		req, err := store.CreateRequest(ctx, storage.Request{HostID: host.ID})
		assert.NoError(t, err, "create request failed")
		requestID = req.ID
		grant, err := store.CreateGrant(ctx, storage.Grant{
			RequestID: req.ID,
			Payload:   map[string]any{"user": "alice"},
		})
		assert.NoError(t, err, "create grant failed")
		grantID = grant.ID
	})

	output := runCLI(t, "--database", dataDir, "inspect", "requests", requestID)

	var response map[string]any
	assert.NoError(t, json.Unmarshal([]byte(output), &response))
	assert.Equal(t, true, response["has_grant"], "has_grant should be true")
	assert.Equal(t, grantID, response["grant_id"], "grant_id should match")
	payload, ok := response["grant_payload"].(map[string]any)
	assert.True(t, ok, "grant_payload should be an object")
	assert.Equal(t, "alice", payload["user"], "grant_payload user should match")
}

func TestCreateRequestCommand(t *testing.T) {
	t.Parallel()

	var hostID string
	var requestSchemaID string
	var grantSchemaID string
	dataDir := prepareTestDataDir(t, func(ctx context.Context, store storage.Store) {
		host, err := store.CreateHost(ctx, storage.Host{})
		assert.NoError(t, err, "create host failed")
		hostID = host.ID
		requestSchema, err := store.CreateSchemaDefinition(ctx, storage.SchemaDefinition{
			Schema: json.RawMessage(`{"type":"object"}`),
		})
		assert.NoError(t, err, "create request schema failed")
		requestSchemaID = requestSchema.ID
		grantSchema, err := store.CreateSchemaDefinition(ctx, storage.SchemaDefinition{
			Schema: json.RawMessage(`{"type":"object"}`),
		})
		assert.NoError(t, err, "create grant schema failed")
		grantSchemaID = grantSchema.ID
	})

	tempDir := t.TempDir()
	payloadPath := filepath.Join(tempDir, "payload.json")
	labelsPath := filepath.Join(tempDir, "labels.json")
	assert.NoError(t, os.WriteFile(payloadPath, []byte(`{"payme":"alot"}`), 0o600))
	assert.NoError(t, os.WriteFile(labelsPath, []byte(`{"env":"dev"}`), 0o600))

	output := runCLI(t,
		"--database", dataDir,
		"create", "requests",
		"--host-id", hostID,
		"--payload-file", payloadPath,
		"--labels-file", labelsPath,
		"--request-schema-id", requestSchemaID,
		"--grant-schema-id", grantSchemaID,
		"--unique-key", "unique-1",
	)

	var response map[string]any
	assert.NoError(t, json.Unmarshal([]byte(output), &response))
	reqID, _ := response["id"].(string)
	assert.NotEmpty(t, reqID, "request id should be set")

	store := openStoreForTesting(t, dataDir)
	defer closeStore(t, store)
	created, err := store.GetRequest(context.Background(), reqID)
	assert.NoError(t, err)
	assert.Equal(t, hostID, created.HostID)
	assert.Equal(t, requestSchemaID, created.RequestSchemaDefinitionID)
	assert.Equal(t, grantSchemaID, created.GrantSchemaDefinitionID)
	assert.Equal(t, "unique-1", created.UniqueKey)
	assert.Equal(t, "dev", created.Labels["env"])
	assert.Equal(t, "alot", created.Payload["payme"])
}

func TestCreateGrantCommand(t *testing.T) {
	t.Parallel()

	var requestID string
	dataDir := prepareTestDataDir(t, func(ctx context.Context, store storage.Store) {
		host, err := store.CreateHost(ctx, storage.Host{})
		assert.NoError(t, err, "create host failed")
		req, err := store.CreateRequest(ctx, storage.Request{HostID: host.ID})
		assert.NoError(t, err, "create request failed")
		requestID = req.ID
	})

	tempDir := t.TempDir()
	payloadPath := filepath.Join(tempDir, "grant.json")
	assert.NoError(t, os.WriteFile(payloadPath, []byte(`{"token":"abc"}`), 0o600))

	output := runCLI(t,
		"--database", dataDir,
		"create", "grants",
		"--request-id", requestID,
		"--payload-file", payloadPath,
	)

	var response map[string]any
	assert.NoError(t, json.Unmarshal([]byte(output), &response))
	grantID, _ := response["id"].(string)
	assert.NotEmpty(t, grantID, "grant id should be set")

	store := openStoreForTesting(t, dataDir)
	defer closeStore(t, store)
	created, err := store.GetGrant(context.Background(), grantID)
	assert.NoError(t, err)
	assert.Equal(t, requestID, created.RequestID)
	assert.Equal(t, "abc", created.Payload["token"])
}

func TestCreateRegisterCommand(t *testing.T) {
	t.Parallel()

	var hostID string
	var schemaID string
	dataDir := prepareTestDataDir(t, func(ctx context.Context, store storage.Store) {
		host, err := store.CreateHost(ctx, storage.Host{})
		assert.NoError(t, err, "create host failed")
		hostID = host.ID
		schema, err := store.CreateSchemaDefinition(ctx, storage.SchemaDefinition{
			Schema: json.RawMessage(`{"type":"object"}`),
		})
		assert.NoError(t, err, "create schema failed")
		schemaID = schema.ID
	})

	tempDir := t.TempDir()
	payloadPath := filepath.Join(tempDir, "register.json")
	labelsPath := filepath.Join(tempDir, "labels.json")
	assert.NoError(t, os.WriteFile(payloadPath, []byte(`{"source":"inttest"}`), 0o600))
	assert.NoError(t, os.WriteFile(labelsPath, []byte(`{"env":"dev"}`), 0o600))

	output := runCLI(t,
		"--database", dataDir,
		"create", "registers",
		"--host-id", hostID,
		"--payload-file", payloadPath,
		"--labels-file", labelsPath,
		"--register-schema-id", schemaID,
		"--unique-key", "reg-unique",
	)

	var response map[string]any
	assert.NoError(t, json.Unmarshal([]byte(output), &response))
	regID, _ := response["id"].(string)
	assert.NotEmpty(t, regID, "register id should be set")

	store := openStoreForTesting(t, dataDir)
	defer closeStore(t, store)
	created, err := store.GetRegister(context.Background(), regID)
	assert.NoError(t, err)
	assert.Equal(t, hostID, created.HostID)
	assert.Equal(t, schemaID, created.SchemaDefinitionID)
	assert.Equal(t, "reg-unique", created.UniqueKey)
	assert.Equal(t, "dev", created.Labels["env"])
	assert.Equal(t, "inttest", created.Payload["source"])
}

func TestCreateSchemaDefinitionCommand(t *testing.T) {
	t.Parallel()

	dataDir := prepareTestDataDir(t, nil)

	tempDir := t.TempDir()
	schemaPath := filepath.Join(tempDir, "schema.json")
	labelsPath := filepath.Join(tempDir, "labels.json")
	assert.NoError(t, os.WriteFile(schemaPath, []byte(`{"type":"object","properties":{"name":{"type":"string"}}}`), 0o600))
	assert.NoError(t, os.WriteFile(labelsPath, []byte(`{"family":"invoice"}`), 0o600))

	output := runCLI(t,
		"--database", dataDir,
		"create", "schema-definitions",
		"--schema-file", schemaPath,
		"--labels-file", labelsPath,
		"--unique-key", "invoice.v1",
	)

	var response map[string]any
	assert.NoError(t, json.Unmarshal([]byte(output), &response))
	defID, _ := response["id"].(string)
	assert.NotEmpty(t, defID, "schema definition id should be set")

	store := openStoreForTesting(t, dataDir)
	defer closeStore(t, store)
	created, err := store.GetSchemaDefinition(context.Background(), defID)
	assert.NoError(t, err)
	assert.Equal(t, "invoice.v1", created.UniqueKey)
	assert.Equal(t, "invoice", created.Labels["family"])
	assert.JSONEq(t, `{"type":"object","properties":{"name":{"type":"string"}}}`, string(created.Schema))
}

func TestMutateSchemaDefinitionLabelsCommand(t *testing.T) {
	t.Parallel()

	var defID string
	dataDir := prepareTestDataDir(t, func(ctx context.Context, store storage.Store) {
		created, err := store.CreateSchemaDefinition(ctx, storage.SchemaDefinition{
			Schema: json.RawMessage(`{"type":"object"}`),
			Labels: map[string]string{"family": "invoice"},
		})
		assert.NoError(t, err, "failed to create schema definition for CLI test")
		defID = created.ID
	})

	cmd := NewRootCommand()
	cmd.SetArgs([]string{
		"--database", dataDir,
		"mutate", "schema-definitions", defID,
		"--labels", `{"family":"updated"}`,
	})
	err := cmd.Execute()
	assert.NoError(t, err, "mutate schema definition labels command failed")

	store := openStoreForTesting(t, dataDir)
	defer closeStore(t, store)

	def, err := store.GetSchemaDefinition(context.Background(), defID)
	assert.NoError(t, err, "GetSchemaDefinition() error")
	assert.Equal(t, "updated", def.Labels["family"], "schema definition labels after mutate via CLI")
}

func TestCreateRequestCommandAPIMode(t *testing.T) {
	t.Parallel()

	payloadFile := filepath.Join(t.TempDir(), "payload.json")
	assert.NoError(t, os.WriteFile(payloadFile, []byte(`{"payme":"alot"}`), 0o600))
	labelsFile := filepath.Join(t.TempDir(), "labels.json")
	assert.NoError(t, os.WriteFile(labelsFile, []byte(`{"env":"api"}`), 0o600))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/requests" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		var payload map[string]any
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
		assert.Equal(t, "host-1", payload["host_id"])
		assert.Equal(t, "req-schema", payload["request_schema_definition_id"])
		assert.Equal(t, "grant-schema", payload["grant_schema_definition_id"])
		assert.Equal(t, "unique-1", payload["unique_key"])
		assert.Equal(t, map[string]any{"payme": "alot"}, payload["payload"])
		assert.Equal(t, map[string]any{"env": "api"}, payload["labels"])
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":      "req-1",
			"host_id": "host-1",
		})
	}))
	defer server.Close()

	cmd := NewRootCommand()
	cmd.SetOut(io.Discard)
	cmd.SetArgs([]string{
		"--backend", "api",
		"--server-url", server.URL,
		"create", "requests",
		"--host-id", "host-1",
		"--payload-file", payloadFile,
		"--labels-file", labelsFile,
		"--request-schema-id", "req-schema",
		"--grant-schema-id", "grant-schema",
		"--unique-key", "unique-1",
	})
	assert.NoError(t, cmd.Execute(), "create request api should succeed")
}

func TestCreateRegisterCommandAPIMode(t *testing.T) {
	t.Parallel()

	payloadFile := filepath.Join(t.TempDir(), "register.json")
	assert.NoError(t, os.WriteFile(payloadFile, []byte(`{"source":"api"}`), 0o600))
	labelsFile := filepath.Join(t.TempDir(), "labels.json")
	assert.NoError(t, os.WriteFile(labelsFile, []byte(`{"env":"api"}`), 0o600))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/registers" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		var payload map[string]any
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
		assert.Equal(t, "host-1", payload["host_id"])
		assert.Equal(t, "schema-1", payload["schema_definition_id"])
		assert.Equal(t, "unique-1", payload["unique_key"])
		assert.Equal(t, map[string]any{"source": "api"}, payload["payload"])
		assert.Equal(t, map[string]any{"env": "api"}, payload["labels"])
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":      "reg-1",
			"host_id": "host-1",
		})
	}))
	defer server.Close()

	cmd := NewRootCommand()
	cmd.SetOut(io.Discard)
	cmd.SetArgs([]string{
		"--backend", "api",
		"--server-url", server.URL,
		"create", "registers",
		"--host-id", "host-1",
		"--payload-file", payloadFile,
		"--labels-file", labelsFile,
		"--register-schema-id", "schema-1",
		"--unique-key", "unique-1",
	})
	assert.NoError(t, cmd.Execute(), "create register api should succeed")
}

func TestCreateGrantCommandAPIMode(t *testing.T) {
	t.Parallel()

	payloadFile := filepath.Join(t.TempDir(), "grant.json")
	assert.NoError(t, os.WriteFile(payloadFile, []byte(`{"token":"abc"}`), 0o600))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/grants" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		var payload map[string]any
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
		assert.Equal(t, "req-1", payload["request_id"])
		assert.Equal(t, map[string]any{"token": "abc"}, payload["payload"])
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":         "grant-1",
			"request_id": "req-1",
		})
	}))
	defer server.Close()

	cmd := NewRootCommand()
	cmd.SetOut(io.Discard)
	cmd.SetArgs([]string{
		"--backend", "api",
		"--server-url", server.URL,
		"create", "grants",
		"--request-id", "req-1",
		"--payload-file", payloadFile,
	})
	assert.NoError(t, cmd.Execute(), "create grant api should succeed")
}

func TestCreateSchemaDefinitionCommandAPIMode(t *testing.T) {
	t.Parallel()

	schemaFile := filepath.Join(t.TempDir(), "schema.json")
	assert.NoError(t, os.WriteFile(schemaFile, []byte(`{"type":"object","required":["name"]}`), 0o600))
	labelsFile := filepath.Join(t.TempDir(), "labels.json")
	assert.NoError(t, os.WriteFile(labelsFile, []byte(`{"family":"invoice"}`), 0o600))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/schema-definitions" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		var payload map[string]any
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
		assert.Equal(t, "invoice.v1", payload["unique_key"])
		assert.Equal(t, map[string]any{"family": "invoice"}, payload["labels"])
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":         "schema-1",
			"unique_key": "invoice.v1",
			"schema":     map[string]any{"type": "object", "required": []string{"name"}},
			"labels":     map[string]any{"family": "invoice"},
		})
	}))
	defer server.Close()

	cmd := NewRootCommand()
	cmd.SetOut(io.Discard)
	cmd.SetArgs([]string{
		"--backend", "api",
		"--server-url", server.URL,
		"create", "schema-definitions",
		"--schema-file", schemaFile,
		"--labels-file", labelsFile,
		"--unique-key", "invoice.v1",
	})
	assert.NoError(t, cmd.Execute(), "create schema definition api should succeed")
}

func TestDeleteHostsCommand(t *testing.T) {
	t.Parallel()

	var hostID string
	dataDir := prepareTestDataDir(t, func(ctx context.Context, store storage.Store) {
		host, err := store.CreateHost(ctx, storage.Host{})
		assert.NoError(t, err, "create host failed")
		hostID = host.ID
	})

	cmd := NewRootCommand()
	cmd.SetOut(io.Discard)
	cmd.SetArgs([]string{"--database", dataDir, "delete", "hosts", hostID})
	assert.NoError(t, cmd.Execute(), "delete hosts command should succeed")

	store := openStoreForTesting(t, dataDir)
	defer closeStore(t, store)
	_, err := store.GetHost(context.Background(), hostID)
	assert.ErrorIs(t, err, storage.ErrHostNotFound)
}

func TestMutateHostsCommand(t *testing.T) {
	t.Parallel()

	var hostID string
	dataDir := prepareTestDataDir(t, func(ctx context.Context, store storage.Store) {
		host, err := store.CreateHost(ctx, storage.Host{})
		assert.NoError(t, err, "create host failed")
		hostID = host.ID
	})

	cmd := NewRootCommand()
	cmd.SetOut(io.Discard)
	cmd.SetArgs([]string{
		"--database", dataDir,
		"mutate", "hosts", hostID,
		"--labels", `{"env":"updated"}`,
	})
	assert.NoError(t, cmd.Execute(), "mutate hosts should succeed")

	store := openStoreForTesting(t, dataDir)
	defer closeStore(t, store)
	host, err := store.GetHost(context.Background(), hostID)
	assert.NoError(t, err)
	assert.Equal(t, "updated", host.Labels["env"])
}

func TestDirectBackendMethods(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	dataDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dataDir, "data"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := server.NamespaceDBPath(dataDir, server.DefaultNamespace)
	store, err := storage.New(ctx, path)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	store.SetNamespace(server.DefaultNamespace)
	defer closeStore(t, store)
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	host, err := store.CreateHost(ctx, storage.Host{Labels: map[string]string{"env": "test"}})
	if err != nil {
		t.Fatalf("create host: %v", err)
	}
	request, err := store.CreateRequest(ctx, storage.Request{HostID: host.ID})
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	reg, err := store.CreateRegister(ctx, storage.Register{HostID: host.ID})
	if err != nil {
		t.Fatalf("create register: %v", err)
	}
	grant, err := store.CreateGrant(ctx, storage.Grant{RequestID: request.ID, Payload: map[string]any{"value": "ok"}})
	if err != nil {
		t.Fatalf("create grant: %v", err)
	}
	def, err := store.CreateSchemaDefinition(ctx, storage.SchemaDefinition{Schema: json.RawMessage(`{"type":"object"}`)})
	if err != nil {
		t.Fatalf("create schema definition: %v", err)
	}

	backend := newDirectBackend(store)

	if _, err := backend.ListHosts(ctx); err != nil {
		t.Fatalf("list hosts: %v", err)
	}
	if _, err := backend.ListRequests(ctx, nil); err != nil {
		t.Fatalf("list requests: %v", err)
	}
	if _, err := backend.ListRegisters(ctx, nil); err != nil {
		t.Fatalf("list registers: %v", err)
	}
	if _, err := backend.ListGrants(ctx); err != nil {
		t.Fatalf("list grants: %v", err)
	}
	if _, err := backend.ListSchemaDefinitions(ctx); err != nil {
		t.Fatalf("list schema definitions: %v", err)
	}
	if _, err := backend.GetHost(ctx, host.ID); err != nil {
		t.Fatalf("get host: %v", err)
	}
	if _, err := backend.GetRequest(ctx, request.ID); err != nil {
		t.Fatalf("get request: %v", err)
	}
	if _, err := backend.GetRegister(ctx, reg.ID); err != nil {
		t.Fatalf("get register: %v", err)
	}
	if _, err := backend.GetGrant(ctx, grant.ID); err != nil {
		t.Fatalf("get grant: %v", err)
	}
	if _, err := backend.GetSchemaDefinition(ctx, def.ID); err != nil {
		t.Fatalf("get schema definition: %v", err)
	}
	if err := backend.UpdateHostLabels(ctx, host.ID, map[string]string{"env": "updated"}); err != nil {
		t.Fatalf("update labels: %v", err)
	}
	if err := backend.DeleteGrant(ctx, grant.ID); err != nil {
		t.Fatalf("delete grant: %v", err)
	}
	if err := backend.DeleteRegister(ctx, reg.ID); err != nil {
		t.Fatalf("delete register: %v", err)
	}
	if err := backend.DeleteRequest(ctx, request.ID); err != nil {
		t.Fatalf("delete request: %v", err)
	}
	if err := backend.DeleteHost(ctx, host.ID); err != nil {
		t.Fatalf("delete host: %v", err)
	}
}

func TestAPIBackendMethods(t *testing.T) {
	t.Parallel()

	host := storage.Host{ID: "api-host"}
	request := storage.Request{ID: "req-1", HostID: host.ID}
	register := storage.Register{ID: "reg-1", HostID: host.ID}
	grant := storage.Grant{ID: "grant-1", RequestID: request.ID}
	def := storage.SchemaDefinition{ID: "schema-1", Schema: json.RawMessage(`{"type":"object"}`)}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); auth != "Bearer tok" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if namespace := r.Header.Get("REMOTE_USER"); namespace != "api-ns" {
			http.Error(w, "missing namespace", http.StatusBadRequest)
			return
		}

		switch {
		case r.URL.Path == "/hosts" && r.Method == http.MethodGet:
			if err := json.NewEncoder(w).Encode([]storage.Host{host}); err != nil {
				t.Errorf("encode hosts: %v", err)
			}
		case r.URL.Path == "/requests" && r.Method == http.MethodGet:
			if err := json.NewEncoder(w).Encode([]storage.Request{request}); err != nil {
				t.Errorf("encode requests: %v", err)
			}
		case r.URL.Path == "/registers" && r.Method == http.MethodGet:
			if err := json.NewEncoder(w).Encode([]storage.Register{register}); err != nil {
				t.Errorf("encode registers: %v", err)
			}
		case r.URL.Path == "/grants" && r.Method == http.MethodGet:
			if err := json.NewEncoder(w).Encode([]storage.Grant{grant}); err != nil {
				t.Errorf("encode grants: %v", err)
			}
		case r.URL.Path == "/schema-definitions" && r.Method == http.MethodGet:
			if err := json.NewEncoder(w).Encode([]storage.SchemaDefinition{def}); err != nil {
				t.Errorf("encode schema definitions: %v", err)
			}
		case r.URL.Path == "/hosts/"+host.ID && r.Method == http.MethodGet:
			if err := json.NewEncoder(w).Encode(host); err != nil {
				t.Errorf("encode host: %v", err)
			}
		case r.URL.Path == "/requests/"+request.ID && r.Method == http.MethodGet:
			if err := json.NewEncoder(w).Encode(request); err != nil {
				t.Errorf("encode request: %v", err)
			}
		case r.URL.Path == "/registers/"+register.ID && r.Method == http.MethodGet:
			if err := json.NewEncoder(w).Encode(register); err != nil {
				t.Errorf("encode register: %v", err)
			}
		case r.URL.Path == "/grants/"+grant.ID && r.Method == http.MethodGet:
			if err := json.NewEncoder(w).Encode(grant); err != nil {
				t.Errorf("encode grant: %v", err)
			}
		case r.URL.Path == "/schema-definitions/"+def.ID && r.Method == http.MethodGet:
			if err := json.NewEncoder(w).Encode(def); err != nil {
				t.Errorf("encode schema definition: %v", err)
			}
		case r.URL.Path == "/schema-definitions" && r.Method == http.MethodPost:
			if _, err := io.ReadAll(r.Body); err != nil {
				t.Errorf("read schema definitions body: %v", err)
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(def); err != nil {
				t.Errorf("encode created schema definition: %v", err)
			}
		case strings.HasPrefix(r.URL.Path, "/schema-definitions/") && strings.HasSuffix(r.URL.Path, "/labels") && r.Method == http.MethodPatch:
			if _, err := io.ReadAll(r.Body); err != nil {
				t.Errorf("read schema labels body: %v", err)
			}
			w.WriteHeader(http.StatusOK)
		case strings.HasPrefix(r.URL.Path, "/hosts/") && strings.HasSuffix(r.URL.Path, "/labels") && r.Method == http.MethodPatch:
			if _, err := io.ReadAll(r.Body); err != nil {
				t.Errorf("read host labels body: %v", err)
			}
			w.WriteHeader(http.StatusOK)
		case strings.HasPrefix(r.URL.Path, "/hosts/") && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		case strings.HasPrefix(r.URL.Path, "/requests/") && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		case strings.HasPrefix(r.URL.Path, "/registers/") && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		case strings.HasPrefix(r.URL.Path, "/grants/") && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		case strings.HasPrefix(r.URL.Path, "/schema-definitions/") && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer server.Close()

	backend, err := newAPIBackend("api-ns", server.URL, "tok", "", "")
	if err != nil {
		t.Fatalf("new api backend: %v", err)
	}

	ctx := context.Background()
	if _, err := backend.ListHosts(ctx); err != nil {
		t.Fatalf("api list hosts: %v", err)
	}
	if _, err := backend.ListRequests(ctx, nil); err != nil {
		t.Fatalf("api list requests: %v", err)
	}
	if _, err := backend.ListRegisters(ctx, nil); err != nil {
		t.Fatalf("api list registers: %v", err)
	}
	if _, err := backend.ListGrants(ctx); err != nil {
		t.Fatalf("api list grants: %v", err)
	}
	if _, err := backend.ListSchemaDefinitions(ctx); err != nil {
		t.Fatalf("api list schema definitions: %v", err)
	}
	if _, err := backend.GetHost(ctx, host.ID); err != nil {
		t.Fatalf("api get host: %v", err)
	}
	if _, err := backend.GetRequest(ctx, request.ID); err != nil {
		t.Fatalf("api get request: %v", err)
	}
	if _, err := backend.GetRegister(ctx, register.ID); err != nil {
		t.Fatalf("api get register: %v", err)
	}
	if _, err := backend.GetGrant(ctx, grant.ID); err != nil {
		t.Fatalf("api get grant: %v", err)
	}
	if _, err := backend.GetSchemaDefinition(ctx, def.ID); err != nil {
		t.Fatalf("api get schema definition: %v", err)
	}
	if _, err := backend.CreateSchemaDefinition(ctx, def); err != nil {
		t.Fatalf("api create schema definition: %v", err)
	}
	if err := backend.UpdateHostLabels(ctx, host.ID, map[string]string{"env": "api-val"}); err != nil {
		t.Fatalf("api update labels: %v", err)
	}
	if err := backend.DeleteGrant(ctx, grant.ID); err != nil {
		t.Fatalf("api delete grant: %v", err)
	}
	if err := backend.DeleteRegister(ctx, register.ID); err != nil {
		t.Fatalf("api delete register: %v", err)
	}
	if err := backend.DeleteRequest(ctx, request.ID); err != nil {
		t.Fatalf("api delete request: %v", err)
	}
	if err := backend.DeleteHost(ctx, host.ID); err != nil {
		t.Fatalf("api delete host: %v", err)
	}
	if err := backend.UpdateSchemaDefinitionLabels(ctx, def.ID, map[string]string{"family": "api-val"}); err != nil {
		t.Fatalf("api update schema definition labels: %v", err)
	}
	if err := backend.DeleteSchemaDefinition(ctx, def.ID); err != nil {
		t.Fatalf("api delete schema definition: %v", err)
	}
}

func TestListCommandsForAllResources(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/hosts":
			if err := json.NewEncoder(w).Encode([]storage.Host{{ID: "list-host"}}); err != nil {
				t.Errorf("encode hosts response: %v", err)
			}
		case "/requests":
			if err := json.NewEncoder(w).Encode([]storage.Request{{ID: "list-req"}}); err != nil {
				t.Errorf("encode requests response: %v", err)
			}
		case "/registers":
			if err := json.NewEncoder(w).Encode([]storage.Register{{ID: "list-reg"}}); err != nil {
				t.Errorf("encode registers response: %v", err)
			}
		case "/grants":
			if err := json.NewEncoder(w).Encode([]storage.Grant{{ID: "list-grant"}}); err != nil {
				t.Errorf("encode grants response: %v", err)
			}
		case "/schema-definitions":
			if err := json.NewEncoder(w).Encode([]storage.SchemaDefinition{{ID: "list-schema"}}); err != nil {
				t.Errorf("encode schema definitions response: %v", err)
			}
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer server.Close()

	for _, resource := range []string{"hosts", "requests", "registers", "grants", "schema-definitions"} {
		cmd := NewRootCommand()
		cmd.SetOut(io.Discard)
		cmd.SetArgs([]string{"--backend", "api", "--server-url", server.URL, "list", resource})
		assert.NoError(t, cmd.Execute(), "listing resource %s should succeed", resource)
	}
}

func TestDeleteCommandsForAllResources(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		switch {
		case strings.HasPrefix(r.URL.Path, "/hosts/"):
			w.WriteHeader(http.StatusNoContent)
		case strings.HasPrefix(r.URL.Path, "/requests/"):
			w.WriteHeader(http.StatusNoContent)
		case strings.HasPrefix(r.URL.Path, "/registers/"):
			w.WriteHeader(http.StatusNoContent)
		case strings.HasPrefix(r.URL.Path, "/grants/"):
			w.WriteHeader(http.StatusNoContent)
		case strings.HasPrefix(r.URL.Path, "/schema-definitions/"):
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer server.Close()

	for _, resource := range []string{"hosts", "requests", "registers", "grants", "schema-definitions"} {
		cmd := NewRootCommand()
		cmd.SetOut(io.Discard)
		cmd.SetArgs([]string{"--backend", "api", "--server-url", server.URL, "delete", resource, "id"})
		assert.NoError(t, cmd.Execute(), "delete resource %s should succeed", resource)
	}
}

func TestInspectRequestAPIWithoutGrant(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, "/requests/") {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":        "req-no-grant",
			"host_id":   "host-1",
			"has_grant": false,
			"grant":     nil,
		})
	}))
	defer server.Close()

	output := runCLI(t, "--backend", "api", "--server-url", server.URL, "inspect", "requests", "req-no-grant")

	var response map[string]any
	assert.NoError(t, json.Unmarshal([]byte(output), &response))
	assert.Equal(t, false, response["has_grant"], "has_grant should be false")
	_, hasGrantID := response["grant_id"]
	assert.False(t, hasGrantID, "grant_id should be absent without grant")
	_, hasGrantPayload := response["grant_payload"]
	assert.False(t, hasGrantPayload, "grant_payload should be absent without grant")
}

func TestInspectRequestAPIWithGrant(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, "/requests/") {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":        "req-grant",
			"host_id":   "host-1",
			"has_grant": true,
			"grant_id":  "grant-1",
			"grant": map[string]any{
				"grant_id": "grant-1",
				"payload":  map[string]any{"user": "alice"},
			},
		})
	}))
	defer server.Close()

	output := runCLI(t, "--backend", "api", "--server-url", server.URL, "inspect", "requests", "req-grant")

	var response map[string]any
	assert.NoError(t, json.Unmarshal([]byte(output), &response))
	assert.Equal(t, true, response["has_grant"], "has_grant should be true")
	assert.Equal(t, "grant-1", response["grant_id"], "grant_id should match")
	payload, ok := response["grant_payload"].(map[string]any)
	assert.True(t, ok, "grant_payload should be an object")
	assert.Equal(t, "alice", payload["user"], "grant_payload user should match")
}

func prepareTestDataDir(t *testing.T, setup func(context.Context, storage.Store)) string {
	t.Helper()

	dataDir := filepath.Join(t.TempDir(), "data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		assert.NoError(t, err, "MkdirAll() error")
		t.FailNow()
	}

	ctx := context.Background()
	path := server.NamespaceDBPath(dataDir, server.DefaultNamespace)
	store, err := storage.New(ctx, path)
	if err != nil {
		assert.NoError(t, err, "New() error")
		t.FailNow()
	}
	store.SetNamespace(server.DefaultNamespace)
	defer closeStore(t, store)

	if err := store.Migrate(ctx); err != nil {
		assert.NoError(t, err, "Migrate() error")
		t.FailNow()
	}

	if setup != nil {
		setup(ctx, store)
	}
	return dataDir
}

func openStoreForTesting(t *testing.T, dataDir string) storage.Store {
	t.Helper()

	path := server.NamespaceDBPath(dataDir, server.DefaultNamespace)
	store, err := storage.New(context.Background(), path)
	if err != nil {
		assert.NoError(t, err, "New() error")
		t.FailNow()
	}
	store.SetNamespace(server.DefaultNamespace)
	return store
}
