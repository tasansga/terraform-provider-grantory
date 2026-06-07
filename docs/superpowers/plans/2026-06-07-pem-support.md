# PEM Support for grantory_host Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Allow users to provide Ed25519 keys in PEM format (PKCS#8 for private, SPKI for public) to the `grantory_host` resource by adding a `key_format` discriminator.

**Architecture:** The provider will handle PEM-to-hex conversion internally before sending requests to the API. It will preserve the user's original PEM input in the Terraform state to avoid drift.

**Tech Stack:** Go (Standard Library: `crypto/ed25519`, `crypto/x509`, `encoding/pem`, `encoding/hex`), Terraform Plugin SDK v2.

---

### Task 1: Add `key_format` to `grantory_host` Schema

**Files:**
- Modify: `internal/provider/resource_host.go`

- [ ] **Step 1: Update the schema in `resourceHost()`**

Add the `key_format` attribute to the schema.

```go
// internal/provider/resource_host.go around line 35
			"key_format": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "hex",
				ForceNew:    true,
				Description: "Format of the public and private keys provided as input. Use \"pem\" for PKCS#8 (private) and SPKI (public) PEM formats.",
				ValidateFunc: validation.StringInSlice([]string{"hex", "pem"}, false),
			},
```

- [ ] **Step 2: Add `github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation` to imports**

```go
import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation" // Add this
)
```

- [ ] **Step 3: Run `go build ./...` to verify schema compilation**

Run: `go build ./internal/provider/...`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/provider/resource_host.go
git commit -m "schema: add key_format to grantory_host"
```

---

### Task 2: Implement `decodeKey` Helper

**Files:**
- Modify: `internal/provider/helpers.go`
- Create: `internal/provider/helpers_test.go`

- [ ] **Step 1: Add necessary imports to `helpers.go`**

```go
import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509" // Add this
	"encoding/hex"
	"encoding/json"
	"encoding/pem" // Add this
	"fmt"
	"os"
	"strings"
    // ...
)
```

- [ ] **Step 2: Implement `decodeKey` function in `helpers.go`**

```go
// internal/provider/helpers.go

func decodeKey(input, format string, isPrivate bool) ([]byte, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, nil
	}

	if format == "hex" {
		keyBytes, err := hex.DecodeString(input)
		if err != nil {
			return nil, fmt.Errorf("failed to decode hex key: %w", err)
		}
		return keyBytes, nil
	}

	if format == "pem" {
		block, _ := pem.Decode([]byte(input))
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM block: no PEM data found")
		}

		if isPrivate {
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
			}
			priv, ok := key.(ed25519.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("expected Ed25519 private key, got %T", key)
			}
			return []byte(priv), nil
		} else {
			key, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse SPKI public key: %w", err)
			}
			pub, ok := key.(ed25519.PublicKey)
			if !ok {
				return nil, fmt.Errorf("expected Ed25519 public key, got %T", key)
			}
			return []byte(pub), nil
		}
	}

	return nil, fmt.Errorf("unsupported key format: %s", format)
}
```

- [ ] **Step 3: Create `internal/provider/helpers_test.go` with unit tests**

```go
package provider

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	pubHex := hex.EncodeToString(pub)
	privHex := hex.EncodeToString(priv)

	pubPKIX, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubPKIX}))

	privPKCS8, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privPKCS8}))

	t.Run("hex public key", func(t *testing.T) {
		got, err := decodeKey(pubHex, "hex", false)
		assert.NoError(t, err)
		assert.Equal(t, []byte(pub), got)
	})

	t.Run("hex private key", func(t *testing.T) {
		got, err := decodeKey(privHex, "hex", true)
		assert.NoError(t, err)
		assert.Equal(t, []byte(priv), got)
	})

	t.Run("pem public key", func(t *testing.T) {
		got, err := decodeKey(pubPEM, "pem", false)
		assert.NoError(t, err)
		assert.Equal(t, []byte(pub), got)
	})

	t.Run("pem private key", func(t *testing.T) {
		got, err := decodeKey(privPEM, "pem", true)
		assert.NoError(t, err)
		assert.Equal(t, []byte(priv), got)
	})

	t.Run("invalid format", func(t *testing.T) {
		_, err := decodeKey(pubHex, "invalid", false)
		assert.Error(t, err)
	})
}
```

- [ ] **Step 4: Run unit tests**

Run: `go test -v internal/provider/helpers.go internal/provider/helpers_test.go`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/provider/helpers.go internal/provider/helpers_test.go
git commit -m "feat: implement decodeKey helper"
```

---

### Task 3: Update `grantory_host` logic to use `decodeKey`

**Files:**
- Modify: `internal/provider/resource_host.go`
- Modify: `internal/provider/helpers.go`

- [ ] **Step 1: Refactor `contextWithPrivateKey` in `helpers.go`**

```go
// internal/provider/helpers.go

func contextWithPrivateKey(ctx context.Context, d *schema.ResourceData) (context.Context, error) {
	var keyInput string
	format := d.Get("key_format").(string)

	if v, ok := d.GetOk("ed25519_private_key"); ok {
		keyInput = v.(string)
	}
	if v, ok := d.GetOk("ed25519_private_key_file"); ok {
		path := strings.TrimSpace(v.(string))
		if path != "" {
			content, err := os.ReadFile(path)
			if err != nil {
				return ctx, fmt.Errorf("failed to read ed25519_private_key_file: %w", err)
			}
			keyInput = string(content)
		}
	}
	if v, ok := d.GetOk("ed25519_private_key_env"); ok {
		envVar := strings.TrimSpace(v.(string))
		if envVar != "" {
			if envVal := os.Getenv(envVar); envVal != "" {
				keyInput = envVal
			}
		}
	}

	keyInput = strings.TrimSpace(keyInput)
	if keyInput == "" {
		return ctx, nil
	}

	keyBytes, err := decodeKey(keyInput, format, true)
	if err != nil {
		return ctx, err
	}

	if len(keyBytes) != ed25519.PrivateKeySize {
		return ctx, fmt.Errorf("invalid ed25519_private_key size: expected %d bytes, got %d", ed25519.PrivateKeySize, len(keyBytes))
	}
	return apiclient.WithPrivateKey(ctx, ed25519.PrivateKey(keyBytes)), nil
}
```

- [ ] **Step 2: Update `resourceHostCreate` in `resource_host.go`**

```go
// internal/provider/resource_host.go

func resourceHostCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*grantoryClient)
	var rawLabels map[string]any
	if value, ok := d.Get("labels").(map[string]any); ok {
		rawLabels = value
	}

	format := d.Get("key_format").(string)
	publicKeyInput := d.Get("public_key").(string)

	var publicKeyHex string
	if publicKeyInput != "" {
		pubBytes, err := decodeKey(publicKeyInput, format, false)
		if err != nil {
			return diag.FromErr(err)
		}
		publicKeyHex = hex.EncodeToString(pubBytes)
	}

	payload := apiHostCreatePayload{
		UniqueKey: d.Get("unique_key").(string),
		PublicKey: publicKeyHex, // Use encoded hex
		Labels:    expandStringMap(rawLabels),
	}

	host, err := client.CreateHost(ctx, payload)
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(host.ID)
	return resourceHostRefresh(ctx, d, host)
}
```

- [ ] **Step 3: Update `resourceHostRefresh` in `resource_host.go`**

Ensure it doesn't overwrite the user's `public_key` if it was PEM. We should only set it if it changed or is missing. Actually, Terraform SDK `d.Set` will handle diffs. If the server returns hex, but we have PEM in state, it might cause a diff if we just `d.Set` the hex value back.

Wait, `resourceHostRefresh` is used after Create, Read, Update.
If the user provides PEM, we store PEM in state.
Server returns hex.
If we `d.Set("public_key", host.PublicKey)` (hex), Terraform will see a diff next time.

We should check if the decoded version of what's in state matches what came from the server.

Actually, the standard way in SDK v2 to handle this is `DiffSuppressFunc`.

- [ ] **Step 4: Add `DiffSuppressFunc` to `public_key` in `resourceHost()`**

```go
// internal/provider/resource_host.go

			"public_key": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "Optional Ed25519 public key in hex or PEM format for signing requests.",
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					format := d.Get("key_format").(string)
					oldBytes, err1 := decodeKey(old, format, false)
					newBytes, err2 := decodeKey(new, format, false)
					if err1 != nil || err2 != nil {
						return false
					}
					return string(oldBytes) == string(newBytes)
				},
			},
```

- [ ] **Step 5: Run tests**

Run: `go test ./internal/provider/...`
Expected: PASS (mostly, since we haven't updated integration tests yet)

- [ ] **Step 6: Commit**

```bash
git add internal/provider/resource_host.go internal/provider/helpers.go
git commit -m "feat: support PEM in grantory_host resource"
```

---

### Task 4: Add Resource Integration Tests for PEM

**Files:**
- Modify: `internal/provider/resource_host_test.go`

- [ ] **Step 1: Add a test case for PEM keys**

```go
// internal/provider/resource_host_test.go

func TestAccResourceHost_PEM(t *testing.T) {
    // ... generate PEM keys ...
    // ... resource.Test with key_format = "pem" ...
}
```

(I will provide the full code during execution)

- [ ] **Step 2: Run acceptance tests**

Run: `TF_ACC=1 go test -v -run TestAccResourceHost_PEM internal/provider/resource_host_test.go`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add internal/provider/resource_host_test.go
git commit -m "test: add acceptance test for PEM keys"
```

---

### Task 5: Update README.md and Documentation

**Files:**
- Modify: `README.md`
- Modify: `docs/resources/host.md` (re-generate)

- [ ] **Step 1: Add `tls_private_key` example to `README.md`**

Add a section "Using with tls_private_key" with the example from the design spec.

- [ ] **Step 2: Re-generate documentation**

Run: `go generate ./...` (or whatever the project uses for documentation generation)

- [ ] **Step 3: Commit**

```bash
git add README.md docs/
git commit -m "docs: add tls_private_key example and update host docs"
```
