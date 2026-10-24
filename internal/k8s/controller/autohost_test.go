package controller

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	clienttest "github.com/tasansga/terraform-provider-grantory/api/client/testutil"
	"github.com/tasansga/terraform-provider-grantory/internal/k8s/api/v1alpha1"
)

func TestEnsureClusterHostCreatesSecretAndHostWhenMissing(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	var createdHost atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/hosts" {
			createdHost.Store(true)
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			if body["unique_key"] != "k8s-cluster" {
				t.Fatalf("expected unique_key k8s-cluster, got %v", body["unique_key"])
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":         "host-cluster-123",
				"unique_key": "k8s-cluster",
				"public_key": body["public_key"],
			})
			return
		}
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	cl := fake.NewClientBuilder().WithScheme(scheme).Build()
	grantoryClient := clienttest.New(t, server, "", "", "")

	identity, err := EnsureClusterHostIdentity(ctx, cl, cl, grantoryClient, ClusterHostOptions{
		HostName:        "k8s-cluster",
		SecretName:      "grantory-cluster-host",
		SecretNamespace: "grantory-system",
	})
	if err != nil {
		t.Fatalf("EnsureClusterHostIdentity: %v", err)
	}

	if identity.HostID != "host-cluster-123" {
		t.Fatalf("expected hostID host-cluster-123, got %s", identity.HostID)
	}
	if len(identity.PrivateKey) != ed25519.PrivateKeySize {
		t.Fatalf("expected 64-byte private key, got %d", len(identity.PrivateKey))
	}
	if !createdHost.Load() {
		t.Fatalf("expected CreateHost to be called on Grantory server")
	}

	var secret corev1.Secret
	if err := cl.Get(ctx, types.NamespacedName{Name: "grantory-cluster-host", Namespace: "grantory-system"}, &secret); err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if string(secret.Data["hostID"]) != "host-cluster-123" {
		t.Fatalf("expected secret hostID host-cluster-123, got %s", string(secret.Data["hostID"]))
	}
}

func TestEnsureClusterHostReusesExistingSecret(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubHex := hex.EncodeToString(pub)
	privHex := hex.EncodeToString(priv)

	var getCalled atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/hosts/host-existing" {
			getCalled.Store(true)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":         "host-existing",
				"unique_key": "k8s-cluster",
				"public_key": pubHex,
			})
			return
		}
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	existingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grantory-cluster-host",
			Namespace: "grantory-system",
		},
		Data: map[string][]byte{
			"hostID":     []byte("host-existing"),
			"publicKey":  []byte(pubHex),
			"privateKey": []byte(privHex),
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingSecret).Build()
	grantoryClient := clienttest.New(t, server, "", "", "")

	identity, err := EnsureClusterHostIdentity(ctx, cl, cl, grantoryClient, ClusterHostOptions{
		HostName:        "k8s-cluster",
		SecretName:      "grantory-cluster-host",
		SecretNamespace: "grantory-system",
	})
	if err != nil {
		t.Fatalf("EnsureClusterHostIdentity: %v", err)
	}

	if identity.HostID != "host-existing" {
		t.Fatalf("expected hostID host-existing, got %s", identity.HostID)
	}
	if !getCalled.Load() {
		t.Fatalf("expected GetHost to be called to verify existing host")
	}
}

func TestEnsureClusterHostReusesPreProvisionedSecretKeyWithoutHostID(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubHex := hex.EncodeToString(pub)
	privHex := hex.EncodeToString(priv)

	var registeredPubHex atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/hosts" {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			registeredPubHex.Store(body["public_key"])
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":         "host-registered-from-preprovisioned",
				"unique_key": "k8s-cluster",
				"public_key": body["public_key"],
			})
			return
		}
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	// Pre-provisioned secret has privateKey and publicKey, but hostID is empty!
	preSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grantory-cluster-host",
			Namespace: "grantory-system",
		},
		Data: map[string][]byte{
			"publicKey":  []byte(pubHex),
			"privateKey": []byte(privHex),
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(preSecret).Build()
	grantoryClient := clienttest.New(t, server, "", "", "")

	identity, err := EnsureClusterHostIdentity(ctx, cl, cl, grantoryClient, ClusterHostOptions{
		HostName:        "k8s-cluster",
		SecretName:      "grantory-cluster-host",
		SecretNamespace: "grantory-system",
	})
	if err != nil {
		t.Fatalf("EnsureClusterHostIdentity: %v", err)
	}

	if identity.HostID != "host-registered-from-preprovisioned" {
		t.Fatalf("expected hostID host-registered-from-preprovisioned, got %s", identity.HostID)
	}
	if registeredPubHex.Load() != pubHex {
		t.Fatalf("expected registered public key %s, got %v", pubHex, registeredPubHex.Load())
	}
	if !identity.PrivateKey.Equal(priv) {
		t.Fatalf("expected pre-provisioned private key to be preserved")
	}
}

func TestEnsureClusterHostFailsOnTransientNetworkErrorWithoutOverwritingSecret(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubHex := hex.EncodeToString(pub)
	privHex := hex.EncodeToString(priv)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate transient 500 error from Grantory server
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	existingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grantory-cluster-host",
			Namespace: "grantory-system",
		},
		Data: map[string][]byte{
			"hostID":     []byte("host-existing"),
			"publicKey":  []byte(pubHex),
			"privateKey": []byte(privHex),
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingSecret).Build()
	grantoryClient := clienttest.New(t, server, "", "", "")

	_, err = EnsureClusterHostIdentity(ctx, cl, cl, grantoryClient, ClusterHostOptions{
		HostName:        "k8s-cluster",
		SecretName:      "grantory-cluster-host",
		SecretNamespace: "grantory-system",
	})
	if err == nil {
		t.Fatalf("expected error on transient server failure, got nil")
	}

	// Verify secret was NOT overwritten!
	var secret corev1.Secret
	if err := cl.Get(ctx, types.NamespacedName{Name: "grantory-cluster-host", Namespace: "grantory-system"}, &secret); err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if string(secret.Data["privateKey"]) != privHex {
		t.Fatalf("secret private key was overwritten during transient error!")
	}
}

func TestEnsureClusterHostFailsFastOn409WithoutLocalSecret(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "host unique key already exists"})
	}))
	defer server.Close()

	cl := fake.NewClientBuilder().WithScheme(scheme).Build()
	grantoryClient := clienttest.New(t, server, "", "", "")

	_, err := EnsureClusterHostIdentity(ctx, cl, cl, grantoryClient, ClusterHostOptions{
		HostName:        "k8s-cluster",
		SecretName:      "grantory-cluster-host",
		SecretNamespace: "grantory-system",
	})
	if err == nil {
		t.Fatalf("expected error when host exists on server but secret missing locally, got nil")
	}
}

func TestRequestReconcileFallsBackToDefaultClusterHostAndKey(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	var hasSig atomic.Bool
	var receivedHostID atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Grantory-Signature") != "" {
			hasSig.Store(true)
		}
		if r.Method == http.MethodPost && r.URL.Path == "/requests" {
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			receivedHostID.Store(body["host_id"])
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":      "req-fallback",
				"host_id": body["host_id"],
			})
			return
		}
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	// Request with NO HostID, NO HostRef, NO PrivateKeySecretRef!
	request := &v1alpha1.GrantoryRequest{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "GrantoryRequest",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "req-auto",
			Namespace:  "default",
			Finalizers: []string{grantoryFinalizer},
		},
		Spec: v1alpha1.GrantoryRequestSpec{
			Payload: `{"app":"test"}`,
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryRequest{}).
		WithObjects(request).
		Build()

	reconciler := &GrantoryRequestReconciler{
		Client:              cl,
		Scheme:              scheme,
		GrantoryClient:      clienttest.New(t, server, "", "", ""),
		DefaultHostProvider: StaticHostProvider{HostID: "cluster-host-default", PrivateKey: priv},
	}

	_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "req-auto", Namespace: "default"}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	gotHost, _ := receivedHostID.Load().(string)
	if gotHost != "cluster-host-default" {
		t.Fatalf("expected host_id cluster-host-default, got %s", gotHost)
	}
	if !hasSig.Load() {
		t.Fatalf("expected request to be signed with default cluster private key")
	}
}

func TestRegisterReconcileFallsBackToDefaultClusterHostAndKey(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	var hasSig atomic.Bool
	var receivedHostID atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Grantory-Signature") != "" {
			hasSig.Store(true)
		}
		if r.Method == http.MethodPost && r.URL.Path == "/registers" {
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			receivedHostID.Store(body["host_id"])
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":      "reg-fallback",
				"host_id": body["host_id"],
			})
			return
		}
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	// Register with NO HostID, NO HostRef, NO PrivateKeySecretRef!
	register := &v1alpha1.GrantoryRegister{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "GrantoryRegister",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "reg-auto",
			Namespace:  "default",
			Finalizers: []string{grantoryFinalizer},
		},
		Spec: v1alpha1.GrantoryRegisterSpec{
			Payload: `{"service":"gatus"}`,
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryRegister{}).
		WithObjects(register).
		Build()

	reconciler := &GrantoryRegisterReconciler{
		Client:              cl,
		Scheme:              scheme,
		GrantoryClient:      clienttest.New(t, server, "", "", ""),
		DefaultHostProvider: StaticHostProvider{HostID: "cluster-host-default", PrivateKey: priv},
	}

	_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "reg-auto", Namespace: "default"}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	gotHost, _ := receivedHostID.Load().(string)
	if gotHost != "cluster-host-default" {
		t.Fatalf("expected host_id cluster-host-default, got %s", gotHost)
	}
	if !hasSig.Load() {
		t.Fatalf("expected register to be signed with default cluster private key")
	}
}

func TestClusterHostBootstrapperLeaderElection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scheme := newTestScheme(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/hosts" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":         "host-cluster-boot",
				"unique_key": "k8s-cluster",
				"public_key": "abc",
			})
			return
		}
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	cl := fake.NewClientBuilder().WithScheme(scheme).Build()
	grantoryClient := clienttest.New(t, server, "", "", "")

	bootstrapper := NewClusterHostBootstrapper(cl, cl, grantoryClient, ClusterHostOptions{
		HostName:        "k8s-cluster",
		SecretName:      "grantory-cluster-host",
		SecretNamespace: "grantory-system",
	})

	if !bootstrapper.NeedLeaderElection() {
		t.Fatalf("expected NeedLeaderElection to be true")
	}

	go func() {
		_ = bootstrapper.Start(ctx)
	}()

	select {
	case <-bootstrapper.ready:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for bootstrapper to be ready")
	}

	hostID, privKey := bootstrapper.GetDefaultHost()
	if hostID != "host-cluster-boot" {
		t.Fatalf("expected hostID host-cluster-boot, got %s", hostID)
	}
	if privKey == nil {
		t.Fatalf("expected non-nil private key")
	}
}

func TestClusterHostBootstrapperIsReadyAndDefensiveCopy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scheme := newTestScheme(t)

	var typedNil *ClusterHostBootstrapper
	if !typedNil.IsReady() {
		t.Fatalf("expected typed nil IsReady to return true")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/hosts" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":         "host-cluster-copy",
				"unique_key": "k8s-cluster",
				"public_key": "abc",
			})
			return
		}
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	cl := fake.NewClientBuilder().WithScheme(scheme).Build()
	grantoryClient := clienttest.New(t, server, "", "", "")

	bootstrapper := NewClusterHostBootstrapper(cl, cl, grantoryClient, ClusterHostOptions{
		HostName:        "k8s-cluster",
		SecretName:      "grantory-cluster-host-copy",
		SecretNamespace: "grantory-system",
	})

	if bootstrapper.IsReady() {
		t.Fatalf("expected bootstrapper not ready before Start")
	}

	go func() {
		_ = bootstrapper.Start(ctx)
	}()

	select {
	case <-bootstrapper.ready:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for bootstrapper to be ready")
	}

	if !bootstrapper.IsReady() {
		t.Fatalf("expected bootstrapper to be ready")
	}

	_, priv1 := bootstrapper.GetDefaultHost()
	priv1[0] ^= 0xFF

	_, priv2 := bootstrapper.GetDefaultHost()
	if priv1[0] == priv2[0] {
		t.Fatalf("expected GetDefaultHost to return a defensive copy, but mutation affected subsequent calls")
	}
}

func TestReconcilerDeletionRequeuesWhenDefaultHostNotReady(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)
	now := metav1.Now()

	req := &v1alpha1.GrantoryRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "del-req",
			Namespace:         "default",
			DeletionTimestamp: &now,
			Finalizers:        []string{grantoryFinalizer},
		},
		Status: v1alpha1.GrantoryRequestStatus{
			ID: "remote-req-1",
		},
	}
	reg := &v1alpha1.GrantoryRegister{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "del-reg",
			Namespace:         "default",
			DeletionTimestamp: &now,
			Finalizers:        []string{grantoryFinalizer},
		},
		Status: v1alpha1.GrantoryRegisterStatus{
			ID: "remote-reg-1",
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryRequest{}, &v1alpha1.GrantoryRegister{}).
		WithObjects(req, reg).
		Build()

	notReadyBootstrapper := NewClusterHostBootstrapper(cl, cl, nil, ClusterHostOptions{})

	reqReconciler := &GrantoryRequestReconciler{
		Client:              cl,
		Scheme:              scheme,
		DefaultHostProvider: notReadyBootstrapper,
	}
	res, err := reqReconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "del-req", Namespace: "default"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.RequeueAfter == 0 {
		t.Fatalf("expected requeue when default host provider is not ready during request deletion")
	}

	regReconciler := &GrantoryRegisterReconciler{
		Client:              cl,
		Scheme:              scheme,
		DefaultHostProvider: notReadyBootstrapper,
	}
	res, err = regReconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "del-reg", Namespace: "default"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.RequeueAfter == 0 {
		t.Fatalf("expected requeue when default host provider is not ready during register deletion")
	}
}

func TestEnsureClusterHostRejectsStaleSecretKeyMismatch(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	pub1, priv1, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub2, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	pub1Hex := hex.EncodeToString(pub1)
	priv1Hex := hex.EncodeToString(priv1)
	pub2Hex := hex.EncodeToString(pub2)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/hosts/host-stale" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":         "host-stale",
				"unique_key": "k8s-cluster",
				"public_key": pub2Hex,
			})
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/hosts" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":         "host-recreated",
				"unique_key": "k8s-cluster",
				"public_key": pub1Hex,
			})
			return
		}
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grantory-cluster-host",
			Namespace: "grantory-system",
		},
		Data: map[string][]byte{
			"hostID":     []byte("host-stale"),
			"publicKey":  []byte(pub1Hex),
			"privateKey": []byte(priv1Hex),
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()
	grantoryClient := clienttest.New(t, server, "", "", "")

	identity, err := EnsureClusterHostIdentity(ctx, cl, cl, grantoryClient, ClusterHostOptions{
		HostName:        "k8s-cluster",
		SecretName:      "grantory-cluster-host",
		SecretNamespace: "grantory-system",
	})
	if err != nil {
		t.Fatalf("EnsureClusterHostIdentity failed: %v", err)
	}

	if identity.HostID == "host-stale" {
		t.Fatalf("expected host-stale to be rejected due to public key mismatch")
	}
	if identity.HostID != "host-recreated" {
		t.Fatalf("expected host-recreated, got %s", identity.HostID)
	}
}

func TestEnsureClusterHost409MismatchProvidesClearError(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	pubMismatch, _, _ := ed25519.GenerateKey(nil)
	pubMismatchHex := hex.EncodeToString(pubMismatch)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/hosts" {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":"host unique_key already exists"}`))
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/hosts" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{
					"id":         "existing-other-key",
					"unique_key": "k8s-cluster",
					"public_key": pubMismatchHex,
				},
			})
			return
		}
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	cl := fake.NewClientBuilder().WithScheme(scheme).Build()
	grantoryClient := clienttest.New(t, server, "", "", "")

	_, err := EnsureClusterHostIdentity(ctx, cl, cl, grantoryClient, ClusterHostOptions{
		HostName:        "k8s-cluster",
		SecretName:      "grantory-cluster-host",
		SecretNamespace: "grantory-system",
	})
	if err == nil {
		t.Fatalf("expected error on 409 mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "already exists in Grantory with a different public key") {
		t.Fatalf("expected descriptive mismatch error, got: %v", err)
	}
}
