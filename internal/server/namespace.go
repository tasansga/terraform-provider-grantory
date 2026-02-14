package server

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/tasansga/terraform-provider-grantory/internal/config"
	"github.com/tasansga/terraform-provider-grantory/internal/storage"
)

const (
	DefaultNamespace   = "_def"
	namespaceMinLength = 4
)

var namespacePattern = regexp.MustCompile(`^[A-Za-z0-9_+,\-\.=:]{4,}$`)

// NamespaceDBPath returns the sqlite file path for the given namespace inside dataDir.
func NamespaceDBPath(dataDir, namespace string) string {
	escaped := url.PathEscape(namespace)
	return filepath.Join(dataDir, escaped+".db")
}

// ValidateNamespaceName ensures the namespace matches the allowed format.
func ValidateNamespaceName(value string) error {
	if value == "" {
		return fmt.Errorf("namespace is required")
	}
	if len(value) < namespaceMinLength {
		return fmt.Errorf("namespace %q must be at least %d characters", value, namespaceMinLength)
	}
	if !namespacePattern.MatchString(value) {
		return fmt.Errorf("namespace %q contains invalid characters", value)
	}
	return nil
}

// NamespaceStore manages sqlite stores split by namespace.
type NamespaceStore struct {
	ctx     context.Context
	dataDir string
	mu      sync.Mutex
	stores  map[string]*storage.Store
}

// NewNamespaceStore creates a manager for the provided data directory.
func NewNamespaceStore(ctx context.Context, dataDir string) (*NamespaceStore, error) {
	if dataDir == "" {
		dataDir = config.DefaultDataDir
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	return &NamespaceStore{
		ctx:     ctx,
		dataDir: dataDir,
		stores:  make(map[string]*storage.Store),
	}, nil
}

// StoreFor returns the sqlite store for namespace, creating it if needed.
func (n *NamespaceStore) StoreFor(ctx context.Context, namespace string) (*storage.Store, error) {
	if err := ValidateNamespaceName(namespace); err != nil {
		return nil, err
	}
	saved := n.get(namespace)
	if saved != nil {
		return saved, nil
	}

	path := NamespaceDBPath(n.dataDir, namespace)
	store, err := storage.New(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("open namespace store: %w", err)
	}
	store.SetNamespace(namespace)

	if err := store.Migrate(n.ctx); err != nil {
		if cerr := store.Close(); cerr != nil {
			return nil, fmt.Errorf("migrate namespace store: %w (close error: %v)", err, cerr)
		}
		return nil, fmt.Errorf("migrate namespace store: %w", err)
	}

	return n.store(namespace, store), nil
}

func (n *NamespaceStore) get(namespace string) *storage.Store {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.stores[namespace]
}

func (n *NamespaceStore) store(namespace string, store *storage.Store) *storage.Store {
	n.mu.Lock()
	defer n.mu.Unlock()
	if existing := n.stores[namespace]; existing != nil {
		if err := store.Close(); err != nil {
			logrus.WithError(err).WithField("namespace", namespace).Warn("close duplicate namespace store")
		}
		return existing
	}
	n.stores[namespace] = store
	return store
}

// Close closes all tracked sqlite stores.
func (n *NamespaceStore) Close() error {
	n.mu.Lock()
	stores := make([]*storage.Store, 0, len(n.stores))
	for _, s := range n.stores {
		stores = append(stores, s)
	}
	n.mu.Unlock()

	var firstErr error
	for _, s := range stores {
		if err := s.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
