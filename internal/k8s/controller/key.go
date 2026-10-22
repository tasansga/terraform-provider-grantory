package controller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	apiclient "github.com/tasansga/terraform-provider-grantory/api/client"
	"github.com/tasansga/terraform-provider-grantory/internal/k8s/api/v1alpha1"
)

func decodeKey(input, format string, isPrivate bool) ([]byte, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, nil
	}

	if strings.HasPrefix(input, "-----BEGIN") {
		format = "pem"
	} else if format == "" {
		format = "hex"
	}

	if strings.EqualFold(format, "hex") {
		keyBytes, err := hex.DecodeString(input)
		if err != nil {
			return nil, fmt.Errorf("failed to decode hex key: %w", err)
		}
		if isPrivate && len(keyBytes) == ed25519.SeedSize {
			keyBytes = ed25519.NewKeyFromSeed(keyBytes)
		}
		return keyBytes, nil
	}

	if strings.EqualFold(format, "pem") {
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
		}

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

	return nil, fmt.Errorf("unsupported key format %q: must be hex or pem", format)
}

func resolvePublicKeyHex(input, format string) (string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", nil
	}
	keyBytes, err := decodeKey(input, format, false)
	if err != nil {
		return "", err
	}
	if len(keyBytes) != ed25519.PublicKeySize {
		return "", fmt.Errorf("invalid public key size: expected %d bytes, got %d", ed25519.PublicKeySize, len(keyBytes))
	}
	return hex.EncodeToString(keyBytes), nil
}

func decodePrivateKey(input, format string) (ed25519.PrivateKey, error) {
	keyBytes, err := decodeKey(input, format, true)
	if err != nil {
		return nil, err
	}
	if len(keyBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid ed25519 private key size: expected %d bytes, got %d", ed25519.PrivateKeySize, len(keyBytes))
	}
	return ed25519.PrivateKey(keyBytes), nil
}

func getSecretBytes(secret *corev1.Secret, key string) ([]byte, bool) {
	if val, ok := secret.Data[key]; ok {
		return val, true
	}
	if strVal, ok := secret.StringData[key]; ok {
		return []byte(strVal), true
	}
	return nil, false
}

func resolvePrivateKey(ctx context.Context, c client.Client, namespace string, ref *v1alpha1.SecretKeyRef, format string) (ed25519.PrivateKey, error) {
	if ref == nil || strings.TrimSpace(ref.Name) == "" {
		return nil, nil
	}

	var secret corev1.Secret
	if err := c.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: namespace}, &secret); err != nil {
		return nil, fmt.Errorf("get private key secret %s/%s: %w", namespace, ref.Name, err)
	}

	var rawKey []byte
	if ref.Key != "" {
		val, ok := getSecretBytes(&secret, ref.Key)
		if !ok {
			return nil, fmt.Errorf("key %q not found in secret %s/%s", ref.Key, namespace, ref.Name)
		}
		rawKey = val
	} else {
		for _, candidate := range []string{"privateKey", "ed25519_private_key", "tls.key", "private_key"} {
			if val, ok := getSecretBytes(&secret, candidate); ok && len(bytes.TrimSpace(val)) > 0 {
				rawKey = val
				break
			}
		}
		if len(rawKey) == 0 {
			return nil, fmt.Errorf("no private key data found in secret %s/%s", namespace, ref.Name)
		}
	}

	privKey, err := decodePrivateKey(string(rawKey), format)
	if err != nil {
		return nil, fmt.Errorf("decode private key from secret %s/%s: %w", namespace, ref.Name, err)
	}

	return privKey, nil
}

func resolveSigningContext(ctx context.Context, c client.Client, ns string, ref *v1alpha1.SecretKeyRef, format, hostID string, hostRef *v1alpha1.HostRef, defaultHostProvider DefaultHostProvider) (context.Context, error) {
	privKey, err := resolvePrivateKey(ctx, c, ns, ref, format)
	if err != nil {
		return ctx, err
	}
	if privKey == nil && defaultHostProvider != nil {
		hasHostRef := hostRef != nil
		defID, defKey := defaultHostProvider.GetDefaultHost()
		if ((hostID == "" && !hasHostRef) || (defID != "" && hostID == defID)) && defKey != nil {
			privKey = defKey
		}
	}
	if privKey != nil {
		ctx = apiclient.WithPrivateKey(ctx, privKey)
	}
	return ctx, nil
}
