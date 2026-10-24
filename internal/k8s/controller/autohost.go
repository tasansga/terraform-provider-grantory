package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	apiclient "github.com/tasansga/terraform-provider-grantory/api/client"
)

type ClusterHostOptions struct {
	UniqueKey       string
	SecretName      string
	SecretNamespace string
	HostLabels      map[string]string
}

type ClusterHostIdentity struct {
	HostID     string
	PublicKey  string
	PrivateKey ed25519.PrivateKey
}

func initialHostLabels(desiredLabels map[string]string) map[string]string {
	labels := make(map[string]string, len(desiredLabels)+3)
	labels["type"] = "cluster"
	for k, v := range desiredLabels {
		if k != "" && v != "" && k != "managed-by" && k != "cluster-host" {
			labels[k] = v
		}
	}
	labels["managed-by"] = "grantory-controller"
	labels["cluster-host"] = "true"
	return labels
}

func syncHostLabels(ctx context.Context, grantoryClient *apiclient.Client, hostID string, existingLabels, desiredLabels map[string]string) error {
	if len(desiredLabels) == 0 {
		return nil
	}
	needsUpdate := false
	merged := make(map[string]string, len(existingLabels)+len(desiredLabels)+2)
	for k, v := range existingLabels {
		merged[k] = v
	}
	for k, v := range desiredLabels {
		if k != "" && v != "" && k != "managed-by" && k != "cluster-host" {
			if existingLabels[k] != v {
				needsUpdate = true
			}
			merged[k] = v
		}
	}
	if merged["managed-by"] != "grantory-controller" {
		merged["managed-by"] = "grantory-controller"
		needsUpdate = true
	}
	if merged["cluster-host"] != "true" {
		merged["cluster-host"] = "true"
		needsUpdate = true
	}
	if !needsUpdate {
		return nil
	}
	_, err := grantoryClient.UpdateHostLabels(ctx, hostID, merged)
	return err
}

func EnsureClusterHostIdentity(ctx context.Context, reader client.Reader, writer client.Writer, grantoryClient *apiclient.Client, opts ClusterHostOptions) (*ClusterHostIdentity, error) {
	uniqueKey := strings.TrimSpace(opts.UniqueKey)
	if uniqueKey == "" {
		uniqueKey = "grantory-cluster"
	}
	secretName := strings.TrimSpace(opts.SecretName)
	if secretName == "" {
		secretName = "grantory-cluster-host"
	}
	secretNamespace := strings.TrimSpace(opts.SecretNamespace)
	if secretNamespace == "" {
		secretNamespace = "grantory-system"
	}

	for attempt := 0; attempt < 5; attempt++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		var secret corev1.Secret
		secretFound := false
		var priv ed25519.PrivateKey
		var pubHex string

		err := reader.Get(ctx, types.NamespacedName{Name: secretName, Namespace: secretNamespace}, &secret)
		if err == nil {
			secretFound = true
			privHexBytes, _ := getSecretBytes(&secret, "privateKey")
			if len(privHexBytes) > 0 {
				decodedPriv, err := decodePrivateKey(string(privHexBytes), "hex")
				if err != nil {
					return nil, fmt.Errorf("decode pre-provisioned private key in secret %s/%s: %w", secretNamespace, secretName, err)
				}
				priv = decodedPriv
				pubHex = hex.EncodeToString(priv.Public().(ed25519.PublicKey))
				hostIDBytes, _ := getSecretBytes(&secret, "hostID")
				hostID := string(hostIDBytes)
				if hostID != "" {
					existing, err := grantoryClient.GetHost(ctx, hostID)
					if err == nil {
						if strings.EqualFold(existing.PublicKey, pubHex) && existing.UniqueKey == uniqueKey {
							if err := syncHostLabels(ctx, grantoryClient, existing.ID, existing.Labels, opts.HostLabels); err != nil {
								return nil, fmt.Errorf("sync cluster host labels: %w", err)
							}
							return &ClusterHostIdentity{
								HostID:     existing.ID,
								PublicKey:  pubHex,
								PrivateKey: priv,
							}, nil
						}
					} else if !apiclient.IsNotFound(err) {
						return nil, fmt.Errorf("verify cluster host on grantory: %w", err)
					}
					// Host was deleted on server or key/name mismatched; proceed to recreate/re-register
				}
			}
		} else if !apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("read cluster host secret: %w", err)
		}

		if priv == nil {
			pub, generatedPriv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return nil, fmt.Errorf("generate ed25519 keypair: %w", err)
			}
			priv = generatedPriv
			pubHex = hex.EncodeToString(pub)

			// Persist keypair to Secret first so private key is never orphaned
			if secretFound {
				if secret.Data == nil {
					secret.Data = make(map[string][]byte)
				}
				secret.Data["publicKey"] = []byte(pubHex)
				secret.Data["privateKey"] = []byte(hex.EncodeToString(priv))
				if err := writer.Update(ctx, &secret); err != nil {
					if apierrors.IsConflict(err) {
						continue
					}
					return nil, fmt.Errorf("persist cluster host keypair: %w", err)
				}
			} else {
				secretObj := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      secretName,
						Namespace: secretNamespace,
					},
					Data: map[string][]byte{
						"publicKey":  []byte(pubHex),
						"privateKey": []byte(hex.EncodeToString(priv)),
					},
				}
				if err := writer.Create(ctx, secretObj); err != nil {
					if apierrors.IsAlreadyExists(err) {
						continue
					}
					return nil, fmt.Errorf("create cluster host secret: %w", err)
				}
				secretFound = true
			}
		}

		privHex := hex.EncodeToString(priv)
		created, err := grantoryClient.CreateHost(ctx, apiclient.HostCreatePayload{
			UniqueKey: uniqueKey,
			PublicKey: pubHex,
			Labels:    initialHostLabels(opts.HostLabels),
		})
		recoveredFromConflict := false
		if err != nil {
			if apiclient.IsConflict(err) || strings.Contains(err.Error(), "already exists") {
				// Recover existing host ID from Grantory server
				hosts, listErr := grantoryClient.ListHosts(ctx)
				if listErr == nil {
					for _, h := range hosts {
						if h.UniqueKey == uniqueKey {
							if strings.EqualFold(h.PublicKey, pubHex) {
								created = apiclient.Host{
									ID:        h.ID,
									UniqueKey: h.UniqueKey,
									PublicKey: h.PublicKey,
									Labels:    h.Labels,
								}
								err = nil
								recoveredFromConflict = true
								break
							} else {
								return nil, fmt.Errorf("cluster host uniqueKey %q already exists in Grantory with a different public key (%s != %s)", uniqueKey, h.PublicKey, pubHex)
							}
						}
					}
				}
			}
			if err != nil {
				return nil, fmt.Errorf("register cluster host on grantory: %w", err)
			}
		}

		if recoveredFromConflict {
			if err := syncHostLabels(ctx, grantoryClient, created.ID, created.Labels, opts.HostLabels); err != nil {
				return nil, fmt.Errorf("sync cluster host labels: %w", err)
			}
		}

		var existingSecret corev1.Secret
		if err := reader.Get(ctx, types.NamespacedName{Name: secretName, Namespace: secretNamespace}, &existingSecret); err == nil {
			if existingSecret.Data == nil {
				existingSecret.Data = make(map[string][]byte)
			}
			existingSecret.Data["hostID"] = []byte(created.ID)
			existingSecret.Data["publicKey"] = []byte(pubHex)
			existingSecret.Data["privateKey"] = []byte(privHex)
			if err := writer.Update(ctx, &existingSecret); err != nil {
				if apierrors.IsConflict(err) {
					continue
				}
				return nil, fmt.Errorf("update cluster host secret: %w", err)
			}
		} else {
			secretObj := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      secretName,
					Namespace: secretNamespace,
				},
				Data: map[string][]byte{
					"hostID":     []byte(created.ID),
					"publicKey":  []byte(pubHex),
					"privateKey": []byte(privHex),
				},
			}
			if err := writer.Create(ctx, secretObj); err != nil {
				if apierrors.IsAlreadyExists(err) {
					continue
				}
				return nil, fmt.Errorf("create cluster host secret: %w", err)
			}
		}

		return &ClusterHostIdentity{
			HostID:     created.ID,
			PublicKey:  pubHex,
			PrivateKey: priv,
		}, nil
	}

	return nil, fmt.Errorf("failed to bootstrap cluster host identity after retries")
}

type DefaultHostProvider interface {
	IsReady() bool
	GetDefaultHost() (string, ed25519.PrivateKey)
}

type StaticHostProvider struct {
	HostID     string
	PrivateKey ed25519.PrivateKey
}

func (s StaticHostProvider) IsReady() bool {
	return true
}

func (s StaticHostProvider) GetDefaultHost() (string, ed25519.PrivateKey) {
	if s.PrivateKey == nil {
		return s.HostID, nil
	}
	keyCopy := make(ed25519.PrivateKey, len(s.PrivateKey))
	copy(keyCopy, s.PrivateKey)
	return s.HostID, keyCopy
}

type ClusterHostBootstrapper struct {
	reader         client.Reader
	writer         client.Writer
	grantoryClient *apiclient.Client
	opts           ClusterHostOptions
	mu             sync.RWMutex
	hostID         string
	privateKey     ed25519.PrivateKey
	ready          chan struct{}
	closeOnce      sync.Once
}

func NewClusterHostBootstrapper(reader client.Reader, writer client.Writer, grantoryClient *apiclient.Client, opts ClusterHostOptions) *ClusterHostBootstrapper {
	return &ClusterHostBootstrapper{
		reader:         reader,
		writer:         writer,
		grantoryClient: grantoryClient,
		opts:           opts,
		ready:          make(chan struct{}),
	}
}

func (b *ClusterHostBootstrapper) NeedLeaderElection() bool {
	return true
}

func (b *ClusterHostBootstrapper) IsReady() bool {
	if b == nil {
		return true
	}
	if b.ready == nil {
		return false
	}
	select {
	case <-b.ready:
		return true
	default:
		return false
	}
}

func (b *ClusterHostBootstrapper) Start(ctx context.Context) error {
	log := ctrl.Log.WithName("cluster-host-bootstrapper")
	backoff := 500 * time.Millisecond
	maxBackoff := 5 * time.Second
	for {
		identity, err := EnsureClusterHostIdentity(ctx, b.reader, b.writer, b.grantoryClient, b.opts)
		if err == nil {
			b.mu.Lock()
			b.hostID = identity.HostID
			b.privateKey = identity.PrivateKey
			b.mu.Unlock()
			b.closeOnce.Do(func() {
				close(b.ready)
			})
			break
		}
		log.Error(err, "Failed to bootstrap cluster host identity; retrying", "backoff", backoff)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
	<-ctx.Done()
	return nil
}

func (b *ClusterHostBootstrapper) GetDefaultHost() (string, ed25519.PrivateKey) {
	if b == nil {
		return "", nil
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.privateKey == nil {
		return b.hostID, nil
	}
	keyCopy := make(ed25519.PrivateKey, len(b.privateKey))
	copy(keyCopy, b.privateKey)
	return b.hostID, keyCopy
}
