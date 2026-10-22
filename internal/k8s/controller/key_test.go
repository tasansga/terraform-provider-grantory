package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/tasansga/terraform-provider-grantory/internal/k8s/api/v1alpha1"
)

func TestParsePrivateKeyHexSeedAndFull(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// 1. Test 64-byte full private key hex
	fullHex := hex.EncodeToString(priv)
	parsedPriv, err := decodePrivateKey(fullHex, "hex")
	if err != nil {
		t.Fatalf("parse full hex: %v", err)
	}
	if !parsedPriv.Equal(priv) {
		t.Fatalf("parsed full hex key does not match")
	}

	// 2. Test 32-byte seed hex
	seed := priv.Seed()
	seedHex := hex.EncodeToString(seed)
	parsedSeedPriv, err := decodePrivateKey(seedHex, "hex")
	if err != nil {
		t.Fatalf("parse seed hex: %v", err)
	}
	if !parsedSeedPriv.Equal(priv) {
		t.Fatalf("parsed seed hex key does not match")
	}
	if !parsedSeedPriv.Public().(ed25519.PublicKey).Equal(pub) {
		t.Fatalf("public key from seed does not match")
	}

	// 3. Test invalid length hex
	if _, err := decodePrivateKey("deadbeef", "hex"); err == nil {
		t.Fatalf("expected error for short hex key")
	}
}

func TestParsePublicKeyHexAndPEM(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// 1. Hex
	pubHex := hex.EncodeToString(pub)
	resolvedHex, err := resolvePublicKeyHex(pubHex, "hex")
	if err != nil {
		t.Fatalf("resolve pub hex: %v", err)
	}
	if resolvedHex != pubHex {
		t.Fatalf("expected %s, got %s", pubHex, resolvedHex)
	}

	// 2. PEM (PKIX SPKI)
	spkiBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal spki: %v", err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spkiBytes}))
	resolvedPEMHex, err := resolvePublicKeyHex(pubPEM, "pem")
	if err != nil {
		t.Fatalf("resolve pub pem: %v", err)
	}
	if resolvedPEMHex != pubHex {
		t.Fatalf("expected %s, got %s", pubHex, resolvedPEMHex)
	}
}

func TestAutoDetectPEMWithoutFormat(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes}))

	// Pass empty format string, should auto-detect PEM because of -----BEGIN
	parsed, err := decodePrivateKey(privPEM, "")
	if err != nil {
		t.Fatalf("auto-detect pem private key failed: %v", err)
	}
	if !parsed.Equal(priv) {
		t.Fatalf("parsed key does not match original")
	}
}

func TestAutoDetectPEMWhenFormatIsDefaultHex(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes}))

	// Even if format is "hex" (the CRD schema default), leading -----BEGIN should auto-detect PEM
	parsed, err := decodePrivateKey(privPEM, "hex")
	if err != nil {
		t.Fatalf("auto-detect pem private key with format=hex failed: %v", err)
	}
	if !parsed.Equal(priv) {
		t.Fatalf("parsed key does not match original")
	}
}

func TestResolvePrivateKeyFromStringData(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	privHex := hex.EncodeToString(priv)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
		},
		StringData: map[string]string{
			"tls.key": privHex,
		},
	}

	cl := fake.NewClientBuilder().WithObjects(secret).Build()
	resolved, err := resolvePrivateKey(context.Background(), cl, "default", &v1alpha1.SecretKeyRef{Name: "test-secret"}, "hex")
	if err != nil {
		t.Fatalf("resolve private key from StringData failed: %v", err)
	}
	if !resolved.Equal(priv) {
		t.Fatalf("resolved key does not match")
	}
}
