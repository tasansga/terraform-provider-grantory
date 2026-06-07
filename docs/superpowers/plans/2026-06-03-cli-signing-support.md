# Grantory CLI Signing Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable Grantory CLI to perform signed write operations using an Ed25519 private key provided via a file.

**Architecture:** Add a new persistent flag `--private-key-file` and environment variable `PRIVATE_KEY_FILE`. Update the CLI's `runWithBackend` logic to load this key and inject it into the API client's context.

**Tech Stack:** Go, Cobra (CLI), Ed25519 (Cryptography).

---

### Task 1: Add Constants for Flags and Environment Variables

**Files:**
- Modify: `internal/cli/flags.go`

- [ ] **Step 1: Add the new flag and environment variable constants**

```go
// Add to internal/cli/flags.go
const (
    // ... existing constants
	FlagPrivateKeyFile             = "private-key-file"
	EnvPrivateKeyFile              = "PRIVATE_KEY_FILE"
)
```

- [ ] **Step 2: Commit**

```bash
git add internal/cli/flags.go
git commit -m "cli: add private-key-file constants"
```

---

### Task 2: Register Persistent Flag in Root Command

**Files:**
- Modify: `internal/cli/root.go`

- [ ] **Step 1: Register the persistent flag**

```go
// In NewRootCommand() in internal/cli/root.go
root.PersistentFlags().String(FlagPrivateKeyFile, "", "path to a file containing a hex-encoded Ed25519 private key (env: "+EnvPrivateKeyFile+")")
```

- [ ] **Step 2: Verify flag registration**

Run: `go run cmd/grantory/main.go --help`
Expected: See `--private-key-file` in the help output.

- [ ] **Step 3: Commit**

```bash
git add internal/cli/root.go
git commit -m "cli: register --private-key-file flag"
```

---

### Task 3: Implement Private Key Loading and Context Injection

**Files:**
- Modify: `internal/cli/cli.go`

- [ ] **Step 1: Implement private key loading logic**

In `runWithBackend`, load the key path, read the file, decode hex, and use `apiclient.WithPrivateKey`.

```go
// In internal/cli/cli.go (inside runWithBackend)
privKeyFile, _ := cmd.Root().PersistentFlags().GetString(FlagPrivateKeyFile)
if privKeyFile == "" {
    privKeyFile = os.Getenv(EnvPrivateKeyFile)
}

if privKeyFile != "" {
    keyHex, err := os.ReadFile(privKeyFile)
    if err != nil {
        return fmt.Errorf("read private key file: %w", err)
    }

    keyBytes, err := hex.DecodeString(strings.TrimSpace(string(keyHex)))
    if err != nil {
        return fmt.Errorf("decode private key hex: %w", err)
    }

    if len(keyBytes) != ed25519.PrivateKeySize {
        return fmt.Errorf("invalid private key size: expected %d bytes, got %d", ed25519.PrivateKeySize, len(keyBytes))
    }

    ctx = apiclient.WithPrivateKey(ctx, ed25519.PrivateKey(keyBytes))
}
```

*Note: You will need to add "crypto/ed25519" and "encoding/hex" to imports.*

- [ ] **Step 2: Commit**

```bash
git add internal/cli/cli.go
git commit -m "cli: implement private key loading in runWithBackend"
```

---

### Task 4: Add Integration Test for CLI Signing

**Files:**
- Create: `internal/cli/signing_test.go`

- [ ] **Step 1: Write integration test**

Create a test that:
1. Starts a test server with `RequireSignatures: true`.
2. Generates a key pair and registers a host with the public key.
3. Writes the private key to a temporary file.
4. Executes a CLI command (e.g., `create requests`) with `--private-key-file`.
5. Verifies success.
6. Verifies failure without the flag.

- [ ] **Step 2: Run tests**

Run: `go test -v ./internal/cli/signing_test.go`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add internal/cli/signing_test.go
git commit -m "cli: add integration test for request signing"
```

---

### Task 5: Final Verification

- [ ] **Step 1: Run all CLI tests**

Run: `go test -v ./internal/cli/...`
Expected: ALL PASS

- [ ] **Step 2: Run lint**

Run: `make lint`
Expected: 0 issues.
