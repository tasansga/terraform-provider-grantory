package store

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"golang.org/x/sync/singleflight"

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

// ErrInvalidNamespace is returned when a namespace name fails validation.
var ErrInvalidNamespace = errors.New("invalid namespace")

// ValidateNamespaceName ensures the namespace matches the allowed format.
func ValidateNamespaceName(value string) error {
	if value == "" {
		return fmt.Errorf("%w: namespace is required", ErrInvalidNamespace)
	}
	if strings.EqualFold(value, "raft") {
		return fmt.Errorf("%w: namespace 'raft' is reserved", ErrInvalidNamespace)
	}
	if len(value) < namespaceMinLength {
		return fmt.Errorf("%w: namespace %q must be at least %d characters", ErrInvalidNamespace, value, namespaceMinLength)
	}
	if !namespacePattern.MatchString(value) {
		return fmt.Errorf("%w: namespace %q contains invalid characters", ErrInvalidNamespace, value)
	}
	return nil
}

// NamespaceStore manages sqlite stores split by namespace.
type NamespaceStore struct {
	database  string
	mu        sync.Mutex
	restoreMu sync.RWMutex
	stores    map[string]storage.Store
	initGroup singleflight.Group
	isClosed  bool
}

// NewNamespaceStore creates a manager for the provided database configuration.
func NewNamespaceStore(_ context.Context, database string) (*NamespaceStore, error) {
	if strings.TrimSpace(database) == "" {
		database = config.DefaultDataDir
	}
	if !storage.IsPostgresDSN(database) {
		if err := os.MkdirAll(database, 0o755); err != nil {
			return nil, fmt.Errorf("create sqlite directory: %w", err)
		}
	}
	return &NamespaceStore{
		database: database,
		stores:   make(map[string]storage.Store),
	}, nil
}

// BeginRestore acquires an exclusive lock on the NamespaceStore, preventing concurrent
// StoreFor calls from accessing or creating databases while a snapshot restore is in progress.
// It returns an unlock function that must be called when the restore completes.
func (n *NamespaceStore) BeginRestore() func() {
	if n == nil {
		return func() {}
	}
	n.restoreMu.Lock()
	return func() {
		n.restoreMu.Unlock()
	}
}

// StoreFor returns the store for namespace, creating it if needed.
//
// Concurrency boundary: n.restoreMu.RLock() protects map lookup and store initialization,
// ensuring stores are not accessed or created while a snapshot restore is in progress.
// However, restoreMu does not guard individual SQL query execution lifetimes once the store
// reference is returned to the caller; snapshot restores acquire restoreMu.Lock() and
// reset/close underlying store instances via Reset().
//
// Note that the context parameter (ctx context.Context) is checked for pre-cancellation
// on entry, but is intentionally not forwarded to store initialization/migration; instead,
// store initialization runs with an internal 30-second timeout context
// (context.WithTimeout(context.Background(), 30*time.Second)) so client cancellations do not
// abort shared migrations. If ctx is canceled while waiting for singleflight initialization,
// StoreFor returns ctx.Err() immediately while the background migration continues.
func (n *NamespaceStore) StoreFor(ctx context.Context, namespace string) (storage.Store, error) {
	if n == nil {
		return nil, errors.New("namespace store is nil")
	}
	if ctx != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err := ValidateNamespaceName(namespace); err != nil {
		return nil, err
	}
	n.restoreMu.RLock()
	defer n.restoreMu.RUnlock()

	n.mu.Lock()
	if n.isClosed {
		n.mu.Unlock()
		return nil, errors.New("namespace store is closed")
	}
	saved := n.stores[namespace]
	n.mu.Unlock()
	if saved != nil {
		return saved, nil
	}

	ch := n.initGroup.DoChan(namespace, func() (any, error) {
		n.mu.Lock()
		if n.isClosed {
			n.mu.Unlock()
			return nil, errors.New("namespace store is closed")
		}
		saved := n.stores[namespace]
		n.mu.Unlock()
		if saved != nil {
			return saved, nil
		}

		initCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		var st storage.Store
		var err error
		if storage.IsPostgresDSN(n.database) {
			st, err = storage.NewPostgres(initCtx, n.database)
		} else {
			path := NamespaceDBPath(n.database, namespace)
			st, err = storage.New(initCtx, path)
		}
		if err != nil {
			return nil, fmt.Errorf("open namespace store: %w", err)
		}
		st.SetNamespace(namespace)

		if err := st.Migrate(initCtx); err != nil {
			if cerr := st.Close(); cerr != nil {
				return nil, fmt.Errorf("migrate namespace store: %w (close error: %v)", err, cerr)
			}
			return nil, fmt.Errorf("migrate namespace store: %w", err)
		}

		stored := n.store(namespace, st)
		if stored == nil {
			return nil, errors.New("namespace store is closed")
		}
		return stored, nil
	})

	var res singleflight.Result
	if ctx != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case res = <-ch:
		}
	} else {
		res = <-ch
	}

	if res.Err != nil {
		return nil, res.Err
	}
	return res.Val.(storage.Store), nil
}

func (n *NamespaceStore) store(namespace string, st storage.Store) storage.Store {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.isClosed {
		if err := st.Close(); err != nil {
			logrus.WithError(err).WithField("namespace", namespace).Warn("close store after namespace store closed")
		}
		return nil
	}
	if existing := n.stores[namespace]; existing != nil {
		if err := st.Close(); err != nil {
			logrus.WithError(err).WithField("namespace", namespace).Warn("close duplicate namespace store")
		}
		return existing
	}
	n.stores[namespace] = st
	return st
}

// DataDir returns the database directory or connection string managed by this store.
func (n *NamespaceStore) DataDir() string {
	if n == nil {
		return ""
	}
	return n.database
}

// ActiveStores returns a snapshot copy of the currently open stores mapped by namespace.
func (n *NamespaceStore) ActiveStores() map[string]storage.Store {
	if n == nil {
		return nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	res := make(map[string]storage.Store, len(n.stores))
	for k, v := range n.stores {
		res[k] = v
	}
	return res
}

// Reset closes all active sqlite stores and clears the internal cache while holding
// restoreMu, preventing concurrent StoreFor calls from accessing stores during teardown.
func (n *NamespaceStore) Reset() error {
	if n == nil {
		return nil
	}
	n.restoreMu.Lock()
	defer n.restoreMu.Unlock()
	return n.ResetLocked()
}

// ResetLocked performs store closure and cache clearing. The caller MUST already hold
// n.restoreMu (e.g. during BeginRestore or Close).
func (n *NamespaceStore) ResetLocked() error {
	if n == nil {
		return nil
	}
	n.mu.Lock()
	stores := make([]storage.Store, 0, len(n.stores))
	for _, s := range n.stores {
		stores = append(stores, s)
	}
	n.stores = make(map[string]storage.Store)
	n.mu.Unlock()

	var firstErr error
	for _, s := range stores {
		if err := s.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Close closes all tracked sqlite stores.
func (n *NamespaceStore) Close() error {
	if n == nil {
		return nil
	}
	n.restoreMu.Lock()
	defer n.restoreMu.Unlock()
	n.mu.Lock()
	n.isClosed = true
	n.mu.Unlock()
	return n.ResetLocked()
}
