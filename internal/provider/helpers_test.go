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

	t.Run("invalid pem public key", func(t *testing.T) {
		_, err := decodeKey("-----BEGIN PUBLIC KEY-----\ninvalid\n-----END PUBLIC KEY-----", "pem", false)
		assert.Error(t, err)
	})

	t.Run("invalid pem private key", func(t *testing.T) {
		_, err := decodeKey("-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----", "pem", true)
		assert.Error(t, err)
	})
}
