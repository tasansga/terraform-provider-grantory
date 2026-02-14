package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tasansga/terraform-provider-grantory/internal/cli"
	"github.com/tasansga/terraform-provider-grantory/internal/config"
	"github.com/tasansga/terraform-provider-grantory/internal/server"
	"github.com/tasansga/terraform-provider-grantory/internal/storage"

	_ "embed"
)

const (
	integrationProviderVersion    = "0.1.0-test"
	integrationRegisterDataSource = "integration-register-source"
)

var (
	//go:embed testdata/integration/main.hcl
	terraformTemplateSource string
	terraformTemplate       = template.Must(template.New("integration").Parse(terraformTemplateSource))

	//go:embed testdata/integration/grant_pipeline.hcl
	terraformGrantTemplateSource string
	terraformGrantTemplate       = template.Must(template.New("grantPipeline").Parse(terraformGrantTemplateSource))

	//go:embed testdata/integration/cli-config.hcl
	cliConfigTemplateSource string
	cliConfigTemplate       = template.Must(template.New("cliConfig").Funcs(template.FuncMap{
		"quote": strconv.Quote,
	}).Parse(cliConfigTemplateSource))
)

type terraformTemplateData struct {
	ProviderVersion    string
	ServerURL          string
	RegisterDataSource string
	RequestLabels      []labelEntry
	RegisterLabels     []labelEntry
}

type labelEntry struct {
	Key   string
	Value string
}

type cliConfigTemplateData struct {
	DevOverridesDir string
}

type grantTemplateData struct {
	ProviderVersion string
	ServerURL       string
	RequestLabels   []labelEntry
	RegisterLabels  []labelEntry
}

func TestIntegrationTerraformApplyUpdatesServer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test that runs Terraform/OpenTofu")
	}

	tofuPath, err := exec.LookPath("tofu")
	if err != nil {
		t.Skipf("tofu binary not found; %v", err)
	}

	workspace := t.TempDir()
	buildDir := filepath.Join(workspace, "provider-bin")
	require.NoError(t, os.MkdirAll(buildDir, 0o755))
	providerBin := filepath.Join(buildDir, "terraform-provider-grantory")
	buildProviderBinary(t, providerBin)

	devDir := filepath.Join(workspace, "terraform-provider-dev")
	require.NoError(t, os.MkdirAll(devDir, 0o755))
	copyFile(t, providerBin, filepath.Join(devDir, "terraform-provider-grantory"))

	serverDataDir := filepath.Join(workspace, "data")
	require.NoError(t, os.MkdirAll(serverDataDir, 0o755))
	serverURL, stopServer := startIntegrationServer(t, serverDataDir)
	t.Cleanup(stopServer)

	initialLabels := map[string]string{"pipeline": "initial"}
	updatedLabels := map[string]string{"pipeline": "integration"}

	tfDir := filepath.Join(workspace, "terraform")
	require.NoError(t, os.MkdirAll(tfDir, 0o755))
	writeTerraformConfig(t, tfDir, serverURL, initialLabels)

	cliConfigPath := filepath.Join(workspace, "terraform.rc")
	writeCLIConfig(t, devDir, cliConfigPath)

	runTofuCommand(t, tofuPath, tfDir, cliConfigPath, "apply", "-input=false", "-auto-approve")

	hosts := listHostsViaCLI(t, serverURL)
	var integrationHost *storage.Host
	for i := range hosts {
		if hosts[i].Labels["env"] == "integration" {
			integrationHost = &hosts[i]
			break
		}
	}
	require.NotNil(t, integrationHost, "expected host created via Terraform")
	require.Equal(t, "integration", integrationHost.Labels["env"])

	requests := listRequestsViaCLI(t, serverURL)
	var foundReq *storage.Request
	for i := range requests {
		if requests[i].Labels["pipeline"] == "initial" {
			foundReq = &requests[i]
			break
		}
	}
	require.NotNil(t, foundReq, "expected request created via Terraform")
	requestID := foundReq.ID
	require.Equal(t, integrationHost.ID, foundReq.HostID)
	require.Equal(t, initialLabels, foundReq.Labels)

	writeTerraformConfig(t, tfDir, serverURL, updatedLabels)
	runTofuCommand(t, tofuPath, tfDir, cliConfigPath, "apply", "-input=false", "-auto-approve")

	requests = listRequestsViaCLI(t, serverURL)
	foundReq = nil
	for i := range requests {
		if requests[i].ID == requestID {
			foundReq = &requests[i]
			break
		}
	}
	require.NotNil(t, foundReq, "expected request to persist after label updates")
	require.Equal(t, updatedLabels, foundReq.Labels)

	grantDir := filepath.Join(workspace, "grant")
	require.NoError(t, os.MkdirAll(grantDir, 0o755))
	writeGrantPipelineConfig(t, grantDir, serverURL, updatedLabels)
	runTofuCommand(t, tofuPath, grantDir, cliConfigPath, "apply", "-input=false", "-auto-approve")

	registers := listRegistersViaCLI(t, serverURL)
	var foundRegister *storage.Register
	for i := range registers {
		if registers[i].HostID == integrationHost.ID {
			foundRegister = &registers[i]
			break
		}
	}
	require.NotNil(t, foundRegister, "expected register created via Terraform")
	sourceValue, ok := foundRegister.Payload["source"].(string)
	require.True(t, ok, "register source should be a string")
	require.Equal(t, integrationRegisterDataSource, sourceValue)

	grants := listGrantsViaCLI(t, serverURL)
	var foundGrant *storage.Grant
	for i := range grants {
		if grants[i].RequestID == requestID {
			foundGrant = &grants[i]
			break
		}
	}
	require.NotNil(t, foundGrant, "expected grant created via Terraform")
	require.Equal(t, requestID, foundGrant.RequestID)

	storePath := server.NamespaceDBPath(serverDataDir, server.DefaultNamespace)
	store, err := storage.New(context.Background(), storePath)
	require.NoError(t, err, "open Grantory store for verification")
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close Grantory store: %v", err)
		}
	})
	store.SetNamespace(server.DefaultNamespace)

	freshRequest, err := store.GetRequest(context.Background(), requestID)
	require.NoError(t, err, "retrieve request after grant creation")
	require.True(t, freshRequest.HasGrant, "request should be marked as granted")
}

func buildProviderBinary(t *testing.T, dst string) {
	t.Helper()
	cmd := exec.Command("go", "build", "-o", dst, "./cmd/terraform-provider-grantory")
	cmd.Dir = filepath.Join("..", "..")
	cmd.Env = os.Environ()
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("go build provider failed: %v\n%s", err, stderr.String())
	}
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	require.NoError(t, err, "read provider binary")
	require.NoError(t, os.WriteFile(dst, data, 0o755), "copy provider binary")
}

func writeTerraformConfig(t *testing.T, dir, serverURL string, labels map[string]string) {
	t.Helper()
	labelEntries := labelEntriesFromMap(labels)

	var buf bytes.Buffer
	data := terraformTemplateData{
		ProviderVersion:    integrationProviderVersion,
		ServerURL:          serverURL,
		RegisterDataSource: integrationRegisterDataSource,
		RequestLabels:      labelEntries,
		RegisterLabels:     labelEntries,
	}
	require.NoError(t, terraformTemplate.Execute(&buf, data), "render Terraform template")

	path := filepath.Join(dir, "main.tf")
	require.NoError(t, os.WriteFile(path, buf.Bytes(), 0o644))
}

func writeGrantPipelineConfig(t *testing.T, dir, serverURL string, labels map[string]string) {
	t.Helper()
	labelEntries := labelEntriesFromMap(labels)

	var buf bytes.Buffer
	data := grantTemplateData{
		ProviderVersion: integrationProviderVersion,
		ServerURL:       serverURL,
		RequestLabels:   labelEntries,
		RegisterLabels:  labelEntries,
	}
	require.NoError(t, terraformGrantTemplate.Execute(&buf, data), "render grant pipeline template")

	path := filepath.Join(dir, "main.tf")
	require.NoError(t, os.WriteFile(path, buf.Bytes(), 0o644))
}

func labelEntriesFromMap(labels map[string]string) []labelEntry {
	if len(labels) == 0 {
		return nil
	}
	entries := make([]labelEntry, 0, len(labels))
	for key, value := range labels {
		entries = append(entries, labelEntry{Key: key, Value: value})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Key < entries[j].Key
	})
	return entries
}

func writeCLIConfig(t *testing.T, devOverrideDir, configPath string) {
	t.Helper()
	absDir, err := filepath.Abs(devOverrideDir)
	require.NoError(t, err, "abs path for dev override")
	var buf bytes.Buffer
	data := cliConfigTemplateData{
		DevOverridesDir: absDir,
	}
	require.NoError(t, cliConfigTemplate.Execute(&buf, data), "render CLI config")
	require.NoError(t, os.WriteFile(configPath, buf.Bytes(), 0o600))
}

func runTofuCommand(t *testing.T, tofuPath, tfDir, cliConfig string, args ...string) {
	t.Helper()
	cmd := exec.Command(tofuPath, args...)
	cmd.Dir = tfDir
	cmd.Env = append(os.Environ(),
		"TF_IN_AUTOMATION=1",
		fmt.Sprintf("TF_CLI_CONFIG_FILE=%s", cliConfig),
		fmt.Sprintf("TOFU_CLI_CONFIG_FILE=%s", cliConfig),
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("tofu %s failed: %v\nstdout:\n%s\nstderr:\n%s",
			strings.Join(args, " "), err, stdout.String(), stderr.String())
	}
}

func listHostsViaCLI(t *testing.T, serverURL string) []storage.Host {
	t.Helper()
	cmd := cli.NewRootCommand()
	cmd.SetArgs([]string{
		"--backend", "api",
		"--server-url", serverURL,
		"list", "hosts",
	})
	output := captureStdout(t, func() {
		require.NoError(t, cmd.Execute(), "list hosts")
	})
	var hosts []storage.Host
	require.NoError(t, json.Unmarshal([]byte(output), &hosts), "parse hosts output")
	return hosts
}

func listRequestsViaCLI(t *testing.T, serverURL string) []storage.Request {
	t.Helper()
	cmd := cli.NewRootCommand()
	cmd.SetArgs([]string{
		"--backend", "api",
		"--server-url", serverURL,
		"list", "requests",
	})
	output := captureStdout(t, func() {
		require.NoError(t, cmd.Execute(), "list requests")
	})
	var requests []storage.Request
	require.NoError(t, json.Unmarshal([]byte(output), &requests), "parse requests output")
	return requests
}

func listRegistersViaCLI(t *testing.T, serverURL string) []storage.Register {
	t.Helper()
	cmd := cli.NewRootCommand()
	cmd.SetArgs([]string{
		"--backend", "api",
		"--server-url", serverURL,
		"list", "registers",
	})
	output := captureStdout(t, func() {
		require.NoError(t, cmd.Execute(), "list registers")
	})
	var registers []storage.Register
	require.NoError(t, json.Unmarshal([]byte(output), &registers), "parse registers output")
	return registers
}

func listGrantsViaCLI(t *testing.T, serverURL string) []storage.Grant {
	t.Helper()
	cmd := cli.NewRootCommand()
	cmd.SetArgs([]string{
		"--backend", "api",
		"--server-url", serverURL,
		"list", "grants",
	})
	output := captureStdout(t, func() {
		require.NoError(t, cmd.Execute(), "list grants")
	})
	var grants []storage.Grant
	require.NoError(t, json.Unmarshal([]byte(output), &grants), "parse grants output")
	return grants
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err, "create pipe")
	os.Stdout = w
	outCh := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		outCh <- buf.String()
	}()
	fn()
	require.NoError(t, w.Close(), "close stdout pipe")
	os.Stdout = old
	output := <-outCh
	require.NoError(t, r.Close(), "close stdout reader")
	return output
}

func startIntegrationServer(t *testing.T, dataDir string) (string, func()) {
	t.Helper()
	port := freePort(t)
	cfg := config.Config{
		DataDir:  dataDir,
		BindAddr: fmt.Sprintf("127.0.0.1:%d", port),
		LogLevel: config.DefaultLogLevel,
	}
	ctx, cancel := context.WithCancel(context.Background())
	srv, err := server.New(ctx, cfg)
	require.NoError(t, err, "start server")

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ctx)
	}()

	waitForServerReady(t, port)

	cleanup := func() {
		cancel()
		if err := srv.Close(); err != nil {
			t.Logf("server close: %v", err)
		}
		select {
		case serveErr := <-errCh:
			if serveErr != nil && !errors.Is(serveErr, context.Canceled) {
				t.Errorf("server exited with error: %v", serveErr)
			}
		case <-time.After(2 * time.Second):
			t.Error("server did not exit in time")
		}
	}
	return fmt.Sprintf("http://127.0.0.1:%d", port), cleanup
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "listen for free port")
	defer func() {
		if err := listener.Close(); err != nil {
			t.Errorf("close free port listener: %v", err)
		}
	}()
	addr := listener.Addr().(*net.TCPAddr)
	return addr.Port
}

func waitForServerReady(t *testing.T, port int) {
	t.Helper()
	url := fmt.Sprintf("http://127.0.0.1:%d/healthz", port)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			if err := resp.Body.Close(); err != nil {
				t.Errorf("close healthz response body: %v", err)
			}
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("server did not become ready at %s", url)
}
