# Design Spec: Grantory CLI Signing Support

**Date:** 2026-06-03
**Status:** Draft

## Purpose
Enable the Grantory CLI to perform signed write operations when interacting with a Grantory server that enforces Ed25519 signatures. This allows CLI users to manage resources for hosts that have a public key registered for security.

## Requirements
1.  **Secure Key Input**: Users must be able to provide an Ed25519 private key without exposing it in the command-line process list (e.g., `ps`).
2.  **Consistent Naming**: Use `--private-key-file` for the flag and `PRIVATE_KEY_FILE` for the environment variable.
3.  **File-Based Input**: Both the flag and the environment variable will point to a file containing the hex-encoded Ed25519 private key.
4.  **Graceful Errors**: Provide clear feedback when key loading or verification fails.

## Architecture

### Configuration (`internal/cli/flags.go`)
- Add `FlagPrivateKeyFile = "private-key-file"`
- Add `EnvPrivateKeyFile = "PRIVATE_KEY_FILE"`

### Registration (`internal/cli/root.go`)
- Register `--private-key-file` as a persistent flag in the root command.
- Ensure it is linked to the `PRIVATE_KEY_FILE` environment variable in `loadConfig`.

### Implementation (`internal/cli/cli.go`)
- Update `runWithBackend` to:
    1. Check for the private key file path from flags or environment.
    2. If a path is provided:
        - Read the file content.
        - Decode the hex-encoded key.
        - Validate it is a valid Ed25519 private key.
        - Wrap the command context using `apiclient.WithPrivateKey(ctx, privKey)`.
    3. If no path is provided, proceed with an unsigned context (server will reject if enforcement is on).

## Error Handling
- **File Not Found**: Error if the specified path does not exist.
- **Invalid Hex**: Error if the file contains non-hex characters.
- **Invalid Key Size**: Error if the decoded bytes do not match `ed25519.PrivateKeySize`.
- **API Error**: If the server rejects the signature, the CLI will pass through the 401 Unauthorized error with the server's message (e.g., "invalid signature", "replay detected").

## Testing Strategy
- **Unit Test**: Verify the key loading and hex decoding logic.
- **Integration Test**:
    1. Start a local Grantory server with `RequireSignatures: true`.
    2. Register a host with a known public key.
    3. Use the CLI with `--private-key-file` pointing to the matching private key.
    4. Verify the operation (e.g., `grantory create request`) succeeds.
    5. Verify it fails when the wrong key or no key is provided.
