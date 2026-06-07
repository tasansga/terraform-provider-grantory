# Design Spec: PEM Support for grantory_host

## Status
- **Date:** 2026-06-07
- **Author:** Gemini CLI
- **Status:** Draft

## Overview
Currently, the `grantory` provider expects Ed25519 public and private keys in hex-encoded format. This makes it difficult to integrate with the `hashicorp/tls` provider, which outputs keys in PEM formats (PKCS#8 for private, SPKI for public).

This design introduces a `key_format` discriminator to the `grantory_host` resource to allow users to explicitly specify that they are providing keys in PEM format.

## User Experience
Users can now wire `tls_private_key` outputs directly into `grantory_host`:

```terraform
resource "tls_private_key" "host_key" {
  algorithm = "ED25519"
}

resource "grantory_host" "app" {
  key_format = "pem"
  public_key = tls_private_key.host_key.public_key_pem
  ed25519_private_key = tls_private_key.host_key.private_key_pem

  labels = {
    env = "prod"
  }
}
```

## Schema Changes
### `grantory_host` (Resource)
- **New Attribute:** `key_format` (String, Optional)
  - **Default:** `"hex"`
  - **Values:** `"hex"`, `"pem"`
  - **Description:** Format of the public and private keys provided as input. Use "pem" for PKCS#8 (private) and SPKI (public) PEM formats.

## Documentation
- **README.md:** Add a prominent example showcasing how to use `tls_private_key` with `grantory_host` to enable host signing. This serves as a key feature showcase for secure host registration.

## Implementation Details
### Internal Logic
1.  **Helper Function:** Implement a robust key decoding helper in `internal/provider/helpers.go`.
    - It will take the raw string input and the `key_format`.
    - If `key_format == "pem"`:
        - Use `pem.Decode` to get the block.
        - For private keys: use `x509.ParsePKCS8PrivateKey`.
        - For public keys: use `x509.ParsePKIXPublicKey`.
        - Validate that the resulting key is of type `ed25519.PrivateKey` or `ed25519.PublicKey`.
        - Return the raw bytes (which the provider will later encode to hex for the API).
    - If `key_format == "hex"`:
        - Continue using the existing `hex.DecodeString` logic.

### Resource State
- The provider will store the exact string provided by the user in the Terraform state. This ensures that the PEM string is preserved and does not cause continuous "dirty" diffs.
- The conversion to hex happens just-in-time when preparing the API request.

## Testing Strategy
1.  **Unit Tests (`internal/provider/helpers_test.go`):**
    - Test decoding of valid hex keys.
    - Test decoding of valid PEM keys (PKCS#8 and SPKI).
    - Test failure cases: invalid PEM, wrong key algorithm (e.g., RSA PEM), invalid hex.
2.  **Integration/Resource Tests (`internal/provider/resource_host_test.go`):**
    - Add a test case that creates, updates, and deletes a `grantory_host` using `key_format = "pem"` and literal PEM strings.

## Alternatives Considered
- **Auto-detection:** Avoided to ensure explicit intent and simpler internal logic.
- **Split format fields:** Avoided to keep the schema clean for the common use case.
