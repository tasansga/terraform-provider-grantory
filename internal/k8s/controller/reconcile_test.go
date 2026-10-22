package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	apiclient "github.com/tasansga/terraform-provider-grantory/api/client"
	clienttest "github.com/tasansga/terraform-provider-grantory/api/client/testutil"
	"github.com/tasansga/terraform-provider-grantory/internal/k8s/api/v1alpha1"
)

func TestRequestReconcileDeletesOutputWhenGrantRevoked(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	request := &v1alpha1.GrantoryRequest{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "GrantoryRequest",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "req",
			Namespace:  "default",
			UID:        types.UID("req-uid"),
			Finalizers: []string{grantoryFinalizer},
		},
		Spec: v1alpha1.GrantoryRequestSpec{
			HostID:          "host-1",
			GrantOutputKind: "secret",
		},
		Status: v1alpha1.GrantoryRequestStatus{
			ID: "req-1",
		},
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "req",
			Namespace:       "default",
			OwnerReferences: []metav1.OwnerReference{ownerRef(request)},
		},
		Data: map[string][]byte{"payload.json": []byte("{}")},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/requests/req-1" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":        "req-1",
			"host_id":   "host-1",
			"has_grant": false,
		})
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryRequest{}).
		WithObjects(request, secret).
		Build()

	reconciler := &GrantoryRequestReconciler{
		Client:         cl,
		Scheme:         scheme,
		GrantoryClient: clienttest.New(t, server, "", "", ""),
	}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "req", Namespace: "default"}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var fetched corev1.Secret
	err = cl.Get(ctx, types.NamespacedName{Name: "req", Namespace: "default"}, &fetched)
	if err == nil || !apierrors.IsNotFound(err) {
		t.Fatalf("expected secret to be deleted, got %v", err)
	}
}

func TestRequestReconcileInvalidPayload(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	request := &v1alpha1.GrantoryRequest{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "GrantoryRequest",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "req",
			Namespace:  "default",
			Finalizers: []string{grantoryFinalizer},
		},
		Spec: v1alpha1.GrantoryRequestSpec{
			HostID:  "host-1",
			Payload: runtime.RawExtension{Raw: []byte(`["x"]`)},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryRequest{}).
		WithObjects(request).
		Build()

	reconciler := &GrantoryRequestReconciler{
		Client:         cl,
		Scheme:         scheme,
		GrantoryClient: clienttest.New(t, server, "", "", ""),
	}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "req", Namespace: "default"}})
	if err == nil {
		t.Fatalf("expected error for invalid payload")
	}

	var updated v1alpha1.GrantoryRequest
	if err := cl.Get(ctx, types.NamespacedName{Name: "req", Namespace: "default"}, &updated); err != nil {
		t.Fatalf("get request: %v", err)
	}
	if !hasConditionReason(updated.Status.Conditions, "InvalidPayload") {
		t.Fatalf("expected InvalidPayload condition, got %+v", updated.Status.Conditions)
	}
}

func TestRequestReconcileRecreatesOnSpecChange(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	request := &v1alpha1.GrantoryRequest{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "GrantoryRequest",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "req",
			Namespace:  "default",
			Finalizers: []string{grantoryFinalizer},
		},
		Spec: v1alpha1.GrantoryRequestSpec{
			HostID:  "host-1",
			Payload: runtime.RawExtension{Raw: []byte(`{"token":"new"}`)},
		},
		Status: v1alpha1.GrantoryRequestStatus{
			ID: "req-1",
		},
	}

	var sawGet atomic.Bool
	var sawDelete atomic.Bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/requests/req-1":
			sawGet.Store(true)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":        "req-1",
				"host_id":   "host-1",
				"payload":   map[string]any{"token": "old"},
				"has_grant": false,
			})
		case r.Method == http.MethodDelete && r.URL.Path == "/requests/req-1":
			sawDelete.Store(true)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryRequest{}).
		WithObjects(request).
		Build()

	reconciler := &GrantoryRequestReconciler{
		Client:         cl,
		Scheme:         scheme,
		GrantoryClient: clienttest.New(t, server, "", "", ""),
	}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "req", Namespace: "default"}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if !sawGet.Load() || !sawDelete.Load() {
		t.Fatalf("expected get and delete, got get=%v delete=%v", sawGet.Load(), sawDelete.Load())
	}

	var updated v1alpha1.GrantoryRequest
	if err := cl.Get(ctx, types.NamespacedName{Name: "req", Namespace: "default"}, &updated); err != nil {
		t.Fatalf("get request: %v", err)
	}
	if updated.Status.ID != "" {
		t.Fatalf("expected status.id to be cleared, got %q", updated.Status.ID)
	}
}

func TestRequestReconcileRequeuesWhenNoGrant(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	request := &v1alpha1.GrantoryRequest{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "GrantoryRequest",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "req",
			Namespace:  "default",
			UID:        types.UID("req-uid"),
			Finalizers: []string{grantoryFinalizer},
		},
		Spec: v1alpha1.GrantoryRequestSpec{
			HostID: "host-1",
		},
		Status: v1alpha1.GrantoryRequestStatus{
			ID: "req-1",
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/requests/req-1" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":        "req-1",
			"host_id":   "host-1",
			"has_grant": false,
		})
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryRequest{}).
		WithObjects(request).
		Build()

	reconciler := &GrantoryRequestReconciler{
		Client:         cl,
		Scheme:         scheme,
		GrantoryClient: clienttest.New(t, server, "", "", ""),
	}

	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "req", Namespace: "default"}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if result.RequeueAfter <= 0 {
		t.Fatalf("expected requeue when no grant, got %v", result.RequeueAfter)
	}
}

func TestRequestReconcileDeletesAllOutputsWhenOutputKindCleared(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	request := &v1alpha1.GrantoryRequest{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "GrantoryRequest",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "req",
			Namespace:  "default",
			UID:        types.UID("req-uid"),
			Finalizers: []string{grantoryFinalizer},
		},
		Spec: v1alpha1.GrantoryRequestSpec{
			HostID: "host-1",
		},
		Status: v1alpha1.GrantoryRequestStatus{
			ID: "req-1",
		},
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "old-secret",
			Namespace:       "default",
			OwnerReferences: []metav1.OwnerReference{ownerRef(request)},
		},
	}
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "old-config",
			Namespace:       "default",
			OwnerReferences: []metav1.OwnerReference{ownerRef(request)},
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/requests/req-1" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":        "req-1",
			"host_id":   "host-1",
			"has_grant": false,
		})
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryRequest{}).
		WithObjects(request, secret, configMap).
		Build()

	reconciler := &GrantoryRequestReconciler{
		Client:         cl,
		Scheme:         scheme,
		GrantoryClient: clienttest.New(t, server, "", "", ""),
	}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "req", Namespace: "default"}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if err := cl.Get(ctx, types.NamespacedName{Name: "old-secret", Namespace: "default"}, &corev1.Secret{}); err == nil || !apierrors.IsNotFound(err) {
		t.Fatalf("expected secret to be deleted, got %v", err)
	}
	if err := cl.Get(ctx, types.NamespacedName{Name: "old-config", Namespace: "default"}, &corev1.ConfigMap{}); err == nil || !apierrors.IsNotFound(err) {
		t.Fatalf("expected configmap to be deleted, got %v", err)
	}
}

func TestRequestReconcileDeletesOldOutputsWhenOutputChanges(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	request := &v1alpha1.GrantoryRequest{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "GrantoryRequest",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "req",
			Namespace:  "default",
			UID:        types.UID("req-uid"),
			Finalizers: []string{grantoryFinalizer},
		},
		Spec: v1alpha1.GrantoryRequestSpec{
			HostID:          "host-1",
			GrantOutputKind: "secret",
			GrantOutputName: "current",
		},
		Status: v1alpha1.GrantoryRequestStatus{
			ID: "req-1",
		},
	}

	oldSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "old-secret",
			Namespace:       "default",
			OwnerReferences: []metav1.OwnerReference{ownerRef(request)},
		},
	}
	oldConfig := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "old-config",
			Namespace:       "default",
			OwnerReferences: []metav1.OwnerReference{ownerRef(request)},
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/requests/req-1" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":        "req-1",
			"host_id":   "host-1",
			"has_grant": true,
			"grant":     map[string]any{"token": "abc"},
		})
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryRequest{}).
		WithObjects(request, oldSecret, oldConfig).
		Build()

	reconciler := &GrantoryRequestReconciler{
		Client:         cl,
		Scheme:         scheme,
		GrantoryClient: clienttest.New(t, server, "", "", ""),
	}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "req", Namespace: "default"}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if err := cl.Get(ctx, types.NamespacedName{Name: "old-secret", Namespace: "default"}, &corev1.Secret{}); err == nil || !apierrors.IsNotFound(err) {
		t.Fatalf("expected old secret to be deleted, got %v", err)
	}
	if err := cl.Get(ctx, types.NamespacedName{Name: "old-config", Namespace: "default"}, &corev1.ConfigMap{}); err == nil || !apierrors.IsNotFound(err) {
		t.Fatalf("expected old configmap to be deleted, got %v", err)
	}
	if err := cl.Get(ctx, types.NamespacedName{Name: "current", Namespace: "default"}, &corev1.Secret{}); err != nil {
		t.Fatalf("expected new secret to exist, got %v", err)
	}
}

func TestRequestReconcileStoresGrantPayloadOnly(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	request := &v1alpha1.GrantoryRequest{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "GrantoryRequest",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "req",
			Namespace:  "default",
			UID:        types.UID("req-uid"),
			Finalizers: []string{grantoryFinalizer},
		},
		Spec: v1alpha1.GrantoryRequestSpec{
			HostID:          "host-1",
			GrantOutputKind: "configmap",
			GrantOutputName: "req-cm",
			GrantOutputKeys: map[string]string{
				"/token": "token",
			},
		},
		Status: v1alpha1.GrantoryRequestStatus{
			ID: "req-1",
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/requests/req-1" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":        "req-1",
			"host_id":   "host-1",
			"has_grant": true,
			"grant": map[string]any{
				"grant_id":   "grant-1",
				"created_at": "2026-03-10T10:00:00Z",
				"updated_at": "2026-03-10T10:00:00Z",
				"payload": map[string]any{
					"token": "abc",
				},
			},
		})
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryRequest{}).
		WithObjects(request).
		Build()

	reconciler := &GrantoryRequestReconciler{
		Client:         cl,
		Scheme:         scheme,
		GrantoryClient: clienttest.New(t, server, "", "", ""),
	}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "req", Namespace: "default"}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var updated v1alpha1.GrantoryRequest
	if err := cl.Get(ctx, types.NamespacedName{Name: "req", Namespace: "default"}, &updated); err != nil {
		t.Fatalf("get request: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(updated.Status.GrantPayload.Raw, &payload); err != nil {
		t.Fatalf("unmarshal grant payload: %v", err)
	}
	if payload["token"] != "abc" {
		t.Fatalf("expected payload token=abc, got %v", payload["token"])
	}
	if _, ok := payload["grant_id"]; ok {
		t.Fatalf("expected grant_id to be stripped from payload")
	}

	var configMap corev1.ConfigMap
	if err := cl.Get(ctx, types.NamespacedName{Name: "req-cm", Namespace: "default"}, &configMap); err != nil {
		t.Fatalf("get configmap: %v", err)
	}
	if got := string(configMap.Data["token"]); got != "abc" {
		t.Fatalf("expected configmap token=abc, got %q", got)
	}
}

func TestHostReconcileAdoptsGrantoryHostID(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	host := &v1alpha1.GrantoryHost{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "GrantoryHost",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "host",
			Namespace: "default",
		},
		Spec: v1alpha1.GrantoryHostSpec{
			GrantoryHostID: "host-remote",
		},
	}

	var sawCreate atomic.Bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/hosts":
			sawCreate.Store(true)
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == "/hosts/host-remote":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "host-remote"})
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryHost{}).
		WithObjects(host).
		Build()

	reconciler := &GrantoryHostReconciler{
		Client:         cl,
		Scheme:         scheme,
		GrantoryClient: clienttest.New(t, server, "", "", ""),
	}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "host", Namespace: "default"}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if sawCreate.Load() {
		t.Fatalf("unexpected host creation")
	}

	var updated v1alpha1.GrantoryHost
	if err := cl.Get(ctx, types.NamespacedName{Name: "host", Namespace: "default"}, &updated); err != nil {
		t.Fatalf("get host: %v", err)
	}
	if updated.Status.ID != "host-remote" {
		t.Fatalf("expected status.id host-remote, got %q", updated.Status.ID)
	}
}

func TestHostReconcileRechecksWhenLabelsUnset(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	host := &v1alpha1.GrantoryHost{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "GrantoryHost",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "host",
			Namespace:  "default",
			Finalizers: []string{grantoryFinalizer},
		},
		Status: v1alpha1.GrantoryHostStatus{
			ID: "gone",
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/hosts/gone" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusNotFound)
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryHost{}).
		WithObjects(host).
		Build()

	reconciler := &GrantoryHostReconciler{
		Client:         cl,
		Scheme:         scheme,
		GrantoryClient: clienttest.New(t, server, "", "", ""),
	}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "host", Namespace: "default"}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var updated v1alpha1.GrantoryHost
	if err := cl.Get(ctx, types.NamespacedName{Name: "host", Namespace: "default"}, &updated); err != nil {
		t.Fatalf("get host: %v", err)
	}
	if updated.Status.ID != "" {
		t.Fatalf("expected status.id to be cleared, got %q", updated.Status.ID)
	}
}

func TestRegisterReconcileRechecksWhenLabelsUnset(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	register := &v1alpha1.GrantoryRegister{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "GrantoryRegister",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "reg",
			Namespace:  "default",
			Finalizers: []string{grantoryFinalizer},
		},
		Spec: v1alpha1.GrantoryRegisterSpec{
			HostID: "host-1",
		},
		Status: v1alpha1.GrantoryRegisterStatus{
			ID: "gone",
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/registers/gone" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusNotFound)
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryRegister{}).
		WithObjects(register).
		Build()

	reconciler := &GrantoryRegisterReconciler{
		Client:         cl,
		Scheme:         scheme,
		GrantoryClient: clienttest.New(t, server, "", "", ""),
	}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "reg", Namespace: "default"}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var updated v1alpha1.GrantoryRegister
	if err := cl.Get(ctx, types.NamespacedName{Name: "reg", Namespace: "default"}, &updated); err != nil {
		t.Fatalf("get register: %v", err)
	}
	if updated.Status.ID != "" {
		t.Fatalf("expected status.id to be cleared, got %q", updated.Status.ID)
	}
}

func TestDeleteOnRemovalDefaultsToTrue(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	var deletedHost atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && r.URL.Path == "/hosts/host-123" {
			deletedHost.Store(true)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	now := metav1.Now()
	// Host with DeleteOnRemoval unset (nil) - should delete by default!
	host := &v1alpha1.GrantoryHost{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "GrantoryHost",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:              "host-del",
			Namespace:         "default",
			Finalizers:        []string{grantoryFinalizer},
			DeletionTimestamp: &now,
		},
		Spec: v1alpha1.GrantoryHostSpec{
			// DeleteOnRemoval is nil/omitted
		},
		Status: v1alpha1.GrantoryHostStatus{
			ID: "host-123",
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryHost{}).
		WithObjects(host).
		Build()

	reconciler := &GrantoryHostReconciler{
		Client:         cl,
		Scheme:         scheme,
		GrantoryClient: clienttest.New(t, server, "", "", ""),
	}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "host-del", Namespace: "default"}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if !deletedHost.Load() {
		t.Fatalf("expected DeleteHost to be called when DeleteOnRemoval is omitted (defaulting to true)")
	}

	var updated v1alpha1.GrantoryHost
	if err := cl.Get(ctx, types.NamespacedName{Name: "host-del", Namespace: "default"}, &updated); err == nil {
		if len(updated.Finalizers) != 0 {
			t.Fatalf("expected finalizer to be removed, got %v", updated.Finalizers)
		}
	}
}

func TestHostAdoptedRetainsOnRemovalByDefault(t *testing.T) {
	host := &v1alpha1.GrantoryHost{
		Spec: v1alpha1.GrantoryHostSpec{
			GrantoryHostID: "ext-host-1",
			// DeleteOnRemoval is nil
		},
	}
	if host.Spec.ShouldDeleteOnRemoval() {
		t.Fatalf("expected adopted host to retain by default on removal")
	}

	delTrue := true
	host.Spec.DeleteOnRemoval = &delTrue
	if host.Spec.ShouldDeleteOnRemoval() {
		t.Fatalf("expected adopted host to NEVER delete on removal, even when DeleteOnRemoval explicitly true")
	}
}

func TestHostReconcileAdoptedHostNotDeletedOnReconcile(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	var deleteCalled atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/hosts/ext-host-1" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":         "ext-host-1",
				"name":       "existing-host",
				"unique_key": "some-unique-key-on-server",
				"public_key": "some-public-key-on-server",
				"labels":     map[string]string{},
			})
			return
		}
		if r.Method == http.MethodDelete {
			deleteCalled.Store(true)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	// Adopted host with status.id already set, and spec.uniqueKey/spec.publicKey omitted
	host := &v1alpha1.GrantoryHost{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "GrantoryHost",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "adopted-host",
			Namespace:  "default",
			Finalizers: []string{grantoryFinalizer},
		},
		Spec: v1alpha1.GrantoryHostSpec{
			GrantoryHostID: "ext-host-1",
		},
		Status: v1alpha1.GrantoryHostStatus{
			ID: "ext-host-1",
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryHost{}).
		WithObjects(host).
		Build()

	reconciler := &GrantoryHostReconciler{
		Client:         cl,
		Scheme:         scheme,
		GrantoryClient: clienttest.New(t, server, "", "", ""),
	}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "adopted-host", Namespace: "default"}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if deleteCalled.Load() {
		t.Fatalf("adopted host must NEVER be deleted during re-reconciliation")
	}

	var updated v1alpha1.GrantoryHost
	if err := cl.Get(ctx, types.NamespacedName{Name: "adopted-host", Namespace: "default"}, &updated); err != nil {
		t.Fatalf("get host: %v", err)
	}
	if updated.Status.ID != "ext-host-1" {
		t.Fatalf("expected status.id to remain ext-host-1, got %q", updated.Status.ID)
	}
}

func TestDeleteOnRemovalRetainsWhenExplicitlyFalse(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	var remoteCalled atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remoteCalled.Store(true)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	now := metav1.Now()
	falseVal := false
	host := &v1alpha1.GrantoryHost{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "GrantoryHost",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:              "host-retain",
			Namespace:         "default",
			Finalizers:        []string{grantoryFinalizer},
			DeletionTimestamp: &now,
		},
		Spec: v1alpha1.GrantoryHostSpec{
			DeleteOnRemoval: &falseVal,
		},
		Status: v1alpha1.GrantoryHostStatus{
			ID: "host-123",
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryHost{}).
		WithObjects(host).
		Build()

	reconciler := &GrantoryHostReconciler{
		Client:         cl,
		Scheme:         scheme,
		GrantoryClient: clienttest.New(t, server, "", "", ""),
	}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "host-retain", Namespace: "default"}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if remoteCalled.Load() {
		t.Fatalf("expected DeleteHost NOT to be called when DeleteOnRemoval is explicitly false")
	}
}

func TestRequestDeleteOnRemovalDefaultsToTrue(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	var deleted atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && r.URL.Path == "/requests/req-123" {
			deleted.Store(true)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	now := metav1.Now()
	request := &v1alpha1.GrantoryRequest{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "GrantoryRequest",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:              "req-del",
			Namespace:         "default",
			Finalizers:        []string{grantoryFinalizer},
			DeletionTimestamp: &now,
		},
		Spec: v1alpha1.GrantoryRequestSpec{
			HostID: "host-1",
		},
		Status: v1alpha1.GrantoryRequestStatus{
			ID: "req-123",
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryRequest{}).
		WithObjects(request).
		Build()

	reconciler := &GrantoryRequestReconciler{
		Client:         cl,
		Scheme:         scheme,
		GrantoryClient: clienttest.New(t, server, "", "", ""),
	}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "req-del", Namespace: "default"}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if !deleted.Load() {
		t.Fatalf("expected DeleteRequest to be called when DeleteOnRemoval is omitted")
	}
}

func TestRegisterDeleteOnRemovalDefaultsToTrue(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	var deleted atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && r.URL.Path == "/registers/reg-123" {
			deleted.Store(true)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	now := metav1.Now()
	register := &v1alpha1.GrantoryRegister{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "GrantoryRegister",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:              "reg-del",
			Namespace:         "default",
			Finalizers:        []string{grantoryFinalizer},
			DeletionTimestamp: &now,
		},
		Spec: v1alpha1.GrantoryRegisterSpec{
			HostID: "host-1",
		},
		Status: v1alpha1.GrantoryRegisterStatus{
			ID: "reg-123",
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryRegister{}).
		WithObjects(register).
		Build()

	reconciler := &GrantoryRegisterReconciler{
		Client:         cl,
		Scheme:         scheme,
		GrantoryClient: clienttest.New(t, server, "", "", ""),
	}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "reg-del", Namespace: "default"}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if !deleted.Load() {
		t.Fatalf("expected DeleteRegister to be called when DeleteOnRemoval is omitted")
	}
}

func TestRegisterReconcileMutableUpdatesPayload(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	var patchCalled atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/registers/reg-1" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":         "reg-1",
				"host_id":    "host-1",
				"unique_key": "reg-key",
				"payload":    map[string]any{"key": "old-val"},
				"mutable":    true,
				"labels":     map[string]string{},
			})
			return
		}
		if r.Method == http.MethodPatch && r.URL.Path == "/registers/reg-1" {
			patchCalled.Store(true)
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode patch body: %v", err)
			}
			payloadMap, ok := body["payload"].(map[string]any)
			if !ok || payloadMap["key"] != "new-val" {
				t.Fatalf("expected payload key=new-val, got %v", body["payload"])
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":         "reg-1",
				"host_id":    "host-1",
				"unique_key": "reg-key",
				"payload":    payloadMap,
				"mutable":    true,
			})
			return
		}
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	register := &v1alpha1.GrantoryRegister{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "GrantoryRegister",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "reg-mut",
			Namespace:  "default",
			Finalizers: []string{grantoryFinalizer},
		},
		Spec: v1alpha1.GrantoryRegisterSpec{
			HostID:    "host-1",
			UniqueKey: "reg-key",
			Mutable:   true,
			Payload:   runtime.RawExtension{Raw: []byte(`{"key":"new-val"}`)},
		},
		Status: v1alpha1.GrantoryRegisterStatus{
			ID: "reg-1",
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryRegister{}).
		WithObjects(register).
		Build()

	reconciler := &GrantoryRegisterReconciler{
		Client:         cl,
		Scheme:         scheme,
		GrantoryClient: clienttest.New(t, server, "", "", ""),
	}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "reg-mut", Namespace: "default"}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if !patchCalled.Load() {
		t.Fatalf("expected PATCH /registers/reg-1 to be called for mutable register payload update")
	}
}

func TestRegisterReconcileImmutableRecreatesOnPayloadChange(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	var deleteCalled atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/registers/reg-1" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":         "reg-1",
				"host_id":    "host-1",
				"unique_key": "reg-key",
				"payload":    map[string]any{"key": "old-val"},
				"mutable":    false,
				"labels":     map[string]string{},
			})
			return
		}
		if r.Method == http.MethodDelete && r.URL.Path == "/registers/reg-1" {
			deleteCalled.Store(true)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	register := &v1alpha1.GrantoryRegister{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "GrantoryRegister",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "reg-immut",
			Namespace:  "default",
			Finalizers: []string{grantoryFinalizer},
		},
		Spec: v1alpha1.GrantoryRegisterSpec{
			HostID:    "host-1",
			UniqueKey: "reg-key",
			Mutable:   false,
			Payload:   runtime.RawExtension{Raw: []byte(`{"key":"new-val"}`)},
		},
		Status: v1alpha1.GrantoryRegisterStatus{
			ID: "reg-1",
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryRegister{}).
		WithObjects(register).
		Build()

	reconciler := &GrantoryRegisterReconciler{
		Client:         cl,
		Scheme:         scheme,
		GrantoryClient: clienttest.New(t, server, "", "", ""),
	}

	res, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "reg-immut", Namespace: "default"}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if !deleteCalled.Load() {
		t.Fatalf("expected DELETE /registers/reg-1 to be called for immutable register payload change")
	}
	if res.RequeueAfter == 0 {
		t.Fatalf("expected requeue after deleting immutable register")
	}
}

func TestRequestReconcileMutableUpdatesInPlace(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	var patchCalled atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/requests/req-1" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":         "req-1",
				"host_id":    "host-1",
				"unique_key": "req-key",
				"payload":    map[string]any{"key": "old-val"},
				"mutable":    true,
				"has_grant":  true,
				"grant_id":   "grant-1",
				"grant":      map[string]any{"secret": "val"},
				"labels":     map[string]string{},
			})
			return
		}
		if r.Method == http.MethodPatch && r.URL.Path == "/requests/req-1" {
			patchCalled.Store(true)
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode patch body: %v", err)
			}
			payloadMap, ok := body["payload"].(map[string]any)
			if !ok || payloadMap["key"] != "new-val" {
				t.Fatalf("expected payload key=new-val, got %v", body["payload"])
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":        "req-1",
				"host_id":   "host-1",
				"payload":   payloadMap,
				"mutable":   true,
				"has_grant": true,
				"grant_id":  "grant-1",
				"grant":     map[string]any{"secret": "val"},
			})
			return
		}
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	request := &v1alpha1.GrantoryRequest{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "GrantoryRequest",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "req-mut",
			Namespace:  "default",
			Finalizers: []string{grantoryFinalizer},
		},
		Spec: v1alpha1.GrantoryRequestSpec{
			HostID:    "host-1",
			UniqueKey: "req-key",
			Mutable:   true,
			Payload:   runtime.RawExtension{Raw: []byte(`{"key":"new-val"}`)},
		},
		Status: v1alpha1.GrantoryRequestStatus{
			ID: "req-1",
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryRequest{}).
		WithObjects(request).
		Build()

	reconciler := &GrantoryRequestReconciler{
		Client:         cl,
		Scheme:         scheme,
		GrantoryClient: clienttest.New(t, server, "", "", ""),
	}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "req-mut", Namespace: "default"}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if !patchCalled.Load() {
		t.Fatalf("expected PATCH /requests/req-1 to be called for mutable request payload update")
	}
}

func TestHostReconcileRegistersPublicKey(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubHex := hex.EncodeToString(pub)

	var receivedPubKey atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/hosts" {
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			receivedPubKey.Store(body["public_key"])
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":         "host-signed",
				"public_key": body["public_key"],
			})
			return
		}
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	host := &v1alpha1.GrantoryHost{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "GrantoryHost",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "host-signed",
			Namespace:  "default",
			Finalizers: []string{grantoryFinalizer},
		},
		Spec: v1alpha1.GrantoryHostSpec{
			PublicKey: pubHex,
			KeyFormat: "hex",
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryHost{}).
		WithObjects(host).
		Build()

	reconciler := &GrantoryHostReconciler{
		Client:         cl,
		Scheme:         scheme,
		GrantoryClient: clienttest.New(t, server, "", "", ""),
	}

	_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "host-signed", Namespace: "default"}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	got, _ := receivedPubKey.Load().(string)
	if got != pubHex {
		t.Fatalf("expected server to receive public key %s, got %s", pubHex, got)
	}
}

func TestRequestReconcileSignsWithSecretKey(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	privHex := hex.EncodeToString(priv)

	var hasSig atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Grantory-Signature") != "" && r.Header.Get("X-Grantory-Timestamp") != "" {
			hasSig.Store(true)
		}
		if r.Method == http.MethodPost && r.URL.Path == "/requests" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":      "req-signed",
				"host_id": "host-1",
			})
			return
		}
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	keySecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "req-key",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"privateKey": []byte(privHex),
		},
	}

	request := &v1alpha1.GrantoryRequest{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "GrantoryRequest",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "req-signed",
			Namespace:  "default",
			Finalizers: []string{grantoryFinalizer},
		},
		Spec: v1alpha1.GrantoryRequestSpec{
			HostID: "host-1",
			PrivateKeySecretRef: &v1alpha1.SecretKeyRef{
				Name: "req-key",
				Key:  "privateKey",
			},
			KeyFormat: "hex",
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryRequest{}).
		WithObjects(keySecret, request).
		Build()

	reconciler := &GrantoryRequestReconciler{
		Client:         cl,
		Scheme:         scheme,
		GrantoryClient: clienttest.New(t, server, "", "", ""),
	}

	_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "req-signed", Namespace: "default"}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if !hasSig.Load() {
		t.Fatalf("expected request to Grantory to be signed with X-Grantory-Signature")
	}
}

func TestHostReconcileRegistersPublicKeyPEM(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubHex := hex.EncodeToString(pub)

	spkiBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal spki: %v", err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spkiBytes}))

	var receivedPubKey atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/hosts" {
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			receivedPubKey.Store(body["public_key"])
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":         "host-pem",
				"public_key": body["public_key"],
			})
			return
		}
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	host := &v1alpha1.GrantoryHost{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "GrantoryHost",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "host-pem",
			Namespace:  "default",
			Finalizers: []string{grantoryFinalizer},
		},
		Spec: v1alpha1.GrantoryHostSpec{
			PublicKey: pubPEM,
			KeyFormat: "pem",
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryHost{}).
		WithObjects(host).
		Build()

	reconciler := &GrantoryHostReconciler{
		Client:         cl,
		Scheme:         scheme,
		GrantoryClient: clienttest.New(t, server, "", "", ""),
	}

	_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "host-pem", Namespace: "default"}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	got, _ := receivedPubKey.Load().(string)
	if got != pubHex {
		t.Fatalf("expected server to receive hex public key %s, got %s", pubHex, got)
	}
}

func TestRegisterReconcileSignsWithSecretKeyPEM(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes}))

	var hasSig atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Grantory-Signature") != "" && r.Header.Get("X-Grantory-Timestamp") != "" {
			hasSig.Store(true)
		}
		if r.Method == http.MethodPost && r.URL.Path == "/registers" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":      "reg-signed",
				"host_id": "host-1",
			})
			return
		}
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	keySecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "reg-key",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"tls.key": []byte(privPEM),
		},
	}

	register := &v1alpha1.GrantoryRegister{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "GrantoryRegister",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "reg-signed",
			Namespace:  "default",
			Finalizers: []string{grantoryFinalizer},
		},
		Spec: v1alpha1.GrantoryRegisterSpec{
			HostID: "host-1",
			PrivateKeySecretRef: &v1alpha1.SecretKeyRef{
				Name: "reg-key",
			},
			KeyFormat: "pem",
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryRegister{}).
		WithObjects(keySecret, register).
		Build()

	reconciler := &GrantoryRegisterReconciler{
		Client:         cl,
		Scheme:         scheme,
		GrantoryClient: clienttest.New(t, server, "", "", ""),
	}

	_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "reg-signed", Namespace: "default"}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if !hasSig.Load() {
		t.Fatalf("expected register to Grantory to be signed with X-Grantory-Signature using PEM key")
	}
}

func TestHostReconcileRejectsImmutablePublicKeyChangeWithoutDeletingHost(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	pub1, _, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	pub1Hex := hex.EncodeToString(pub1)
	pub2Hex := hex.EncodeToString(pub2)

	var deleteCalled atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/hosts/host-1" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":         "host-1",
				"name":       "host-test",
				"public_key": pub1Hex,
				"labels":     map[string]string{},
			})
			return
		}
		if r.Method == http.MethodDelete {
			deleteCalled.Store(true)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	host := &v1alpha1.GrantoryHost{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "GrantoryHost",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "host-test",
			Namespace:  "default",
			Finalizers: []string{grantoryFinalizer},
		},
		Spec: v1alpha1.GrantoryHostSpec{
			PublicKey: pub2Hex,
		},
		Status: v1alpha1.GrantoryHostStatus{
			ID: "host-1",
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryHost{}).
		WithObjects(host).
		Build()

	reconciler := &GrantoryHostReconciler{
		Client:         cl,
		Scheme:         scheme,
		GrantoryClient: clienttest.New(t, server, "", "", ""),
	}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "host-test", Namespace: "default"}})
	if err == nil {
		t.Fatalf("expected error when modifying immutable public key")
	}
	if deleteCalled.Load() {
		t.Fatalf("host must NEVER be deleted when public key changes (prevents cascading deletion)")
	}

	var updated v1alpha1.GrantoryHost
	if err := cl.Get(ctx, types.NamespacedName{Name: "host-test", Namespace: "default"}, &updated); err != nil {
		t.Fatalf("get host: %v", err)
	}
	if updated.Status.ID != "host-1" {
		t.Fatalf("expected status.ID to remain host-1, got %q", updated.Status.ID)
	}
	if !hasConditionReason(updated.Status.Conditions, "ImmutableFieldChanged") {
		t.Fatalf("expected ImmutableFieldChanged condition, got %v", updated.Status.Conditions)
	}
}

func TestRequestReconcileSignedDeletion(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	privHex := hex.EncodeToString(priv)

	var hasSig atomic.Bool
	var deleteCalled atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && r.URL.Path == "/requests/req-signed-del" {
			deleteCalled.Store(true)
			if r.Header.Get("X-Grantory-Signature") != "" && r.Header.Get("X-Grantory-Timestamp") != "" {
				hasSig.Store(true)
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	keySecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "del-key",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"privateKey": []byte(privHex),
		},
	}

	now := metav1.Now()
	request := &v1alpha1.GrantoryRequest{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "GrantoryRequest",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:              "req-signed-del",
			Namespace:         "default",
			Finalizers:        []string{grantoryFinalizer},
			DeletionTimestamp: &now,
		},
		Spec: v1alpha1.GrantoryRequestSpec{
			HostID: "host-1",
			PrivateKeySecretRef: &v1alpha1.SecretKeyRef{
				Name: "del-key",
			},
		},
		Status: v1alpha1.GrantoryRequestStatus{
			ID: "req-signed-del",
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryRequest{}).
		WithObjects(keySecret, request).
		Build()

	reconciler := &GrantoryRequestReconciler{
		Client:         cl,
		Scheme:         scheme,
		GrantoryClient: clienttest.New(t, server, "", "", ""),
	}

	_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "req-signed-del", Namespace: "default"}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if !deleteCalled.Load() {
		t.Fatalf("expected DELETE /requests/req-signed-del to be called")
	}
	if !hasSig.Load() {
		t.Fatalf("expected DELETE /requests/req-signed-del to include X-Grantory-Signature header")
	}

	var updated v1alpha1.GrantoryRequest
	if err := cl.Get(ctx, types.NamespacedName{Name: "req-signed-del", Namespace: "default"}, &updated); err == nil {
		if len(updated.Finalizers) != 0 {
			t.Fatalf("expected finalizers to be removed after successful signed deletion")
		}
	}
}

func TestRegisterReconcileSignedDeletion(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	privHex := hex.EncodeToString(priv)

	var hasSig atomic.Bool
	var deleteCalled atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && r.URL.Path == "/registers/reg-signed-del" {
			deleteCalled.Store(true)
			if r.Header.Get("X-Grantory-Signature") != "" && r.Header.Get("X-Grantory-Timestamp") != "" {
				hasSig.Store(true)
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	keySecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "del-key",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"privateKey": []byte(privHex),
		},
	}

	now := metav1.Now()
	register := &v1alpha1.GrantoryRegister{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "GrantoryRegister",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:              "reg-signed-del",
			Namespace:         "default",
			Finalizers:        []string{grantoryFinalizer},
			DeletionTimestamp: &now,
		},
		Spec: v1alpha1.GrantoryRegisterSpec{
			HostID: "host-1",
			PrivateKeySecretRef: &v1alpha1.SecretKeyRef{
				Name: "del-key",
			},
		},
		Status: v1alpha1.GrantoryRegisterStatus{
			ID: "reg-signed-del",
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryRegister{}).
		WithObjects(keySecret, register).
		Build()

	reconciler := &GrantoryRegisterReconciler{
		Client:         cl,
		Scheme:         scheme,
		GrantoryClient: clienttest.New(t, server, "", "", ""),
	}

	_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "reg-signed-del", Namespace: "default"}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if !deleteCalled.Load() {
		t.Fatalf("expected DELETE /registers/reg-signed-del to be called")
	}
	if !hasSig.Load() {
		t.Fatalf("expected DELETE /registers/reg-signed-del to include X-Grantory-Signature header")
	}

	var updated v1alpha1.GrantoryRegister
	if err := cl.Get(ctx, types.NamespacedName{Name: "reg-signed-del", Namespace: "default"}, &updated); err == nil {
		if len(updated.Finalizers) != 0 {
			t.Fatalf("expected finalizers to be removed after successful signed deletion")
		}
	}
}

func TestRequestReconcileWaitingForSecret(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()

	request := &v1alpha1.GrantoryRequest{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "GrantoryRequest",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "req-missing-secret",
			Namespace:  "default",
			Finalizers: []string{grantoryFinalizer},
		},
		Spec: v1alpha1.GrantoryRequestSpec{
			HostID: "host-1",
			PrivateKeySecretRef: &v1alpha1.SecretKeyRef{
				Name: "non-existent-secret",
			},
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryRequest{}).
		WithObjects(request).
		Build()

	reconciler := &GrantoryRequestReconciler{
		Client:         cl,
		Scheme:         scheme,
		GrantoryClient: clienttest.New(t, server, "", "", ""),
	}

	res, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "req-missing-secret", Namespace: "default"}})
	if err != nil {
		t.Fatalf("expected no hard error when waiting for secret, got %v", err)
	}
	if res.RequeueAfter != 5*time.Second {
		t.Fatalf("expected 5s requeue, got %v", res.RequeueAfter)
	}

	var updated v1alpha1.GrantoryRequest
	if err := cl.Get(ctx, types.NamespacedName{Name: "req-missing-secret", Namespace: "default"}, &updated); err != nil {
		t.Fatalf("get request: %v", err)
	}
	if !hasConditionReason(updated.Status.Conditions, "WaitingForSecret") {
		t.Fatalf("expected WaitingForSecret condition")
	}
}

func TestRegisterReconcileWaitingForSecret(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()

	register := &v1alpha1.GrantoryRegister{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "GrantoryRegister",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "reg-missing-secret",
			Namespace:  "default",
			Finalizers: []string{grantoryFinalizer},
		},
		Spec: v1alpha1.GrantoryRegisterSpec{
			HostID: "host-1",
			PrivateKeySecretRef: &v1alpha1.SecretKeyRef{
				Name: "non-existent-secret",
			},
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryRegister{}).
		WithObjects(register).
		Build()

	reconciler := &GrantoryRegisterReconciler{
		Client:         cl,
		Scheme:         scheme,
		GrantoryClient: clienttest.New(t, server, "", "", ""),
	}

	res, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "reg-missing-secret", Namespace: "default"}})
	if err != nil {
		t.Fatalf("expected no hard error when waiting for secret, got %v", err)
	}
	if res.RequeueAfter != 5*time.Second {
		t.Fatalf("expected 5s requeue, got %v", res.RequeueAfter)
	}

	var updated v1alpha1.GrantoryRegister
	if err := cl.Get(ctx, types.NamespacedName{Name: "reg-missing-secret", Namespace: "default"}, &updated); err != nil {
		t.Fatalf("get register: %v", err)
	}
	if !hasConditionReason(updated.Status.Conditions, "WaitingForSecret") {
		t.Fatalf("expected WaitingForSecret condition")
	}
}

func newTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("add core scheme: %v", err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add grantory scheme: %v", err)
	}
	return scheme
}

func ownerRef(request *v1alpha1.GrantoryRequest) metav1.OwnerReference {
	controller := true
	return metav1.OwnerReference{
		APIVersion: v1alpha1.GroupVersion.String(),
		Kind:       "GrantoryRequest",
		Name:       request.Name,
		UID:        request.UID,
		Controller: &controller,
	}
}

func hasConditionReason(conditions []metav1.Condition, reason string) bool {
	for _, condition := range conditions {
		if condition.Reason == reason {
			return true
		}
	}
	return false
}

func TestResolveSigningContextBypassesDefaultKeyWhenHostRefSet(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	_, defaultPriv, _ := ed25519.GenerateKey(rand.Reader)
	cl := fake.NewClientBuilder().WithScheme(scheme).Build()
	staticProvider := StaticHostProvider{HostID: "cluster-default", PrivateKey: defaultPriv}

	// 1. hostID is empty, but hostRef is explicitly provided -> MUST NOT pick up defaultPrivKey
	signedCtx, err := resolveSigningContext(ctx, cl, "default", nil, "", "", &v1alpha1.HostRef{Name: "ext-host"}, staticProvider)
	if err != nil {
		t.Fatalf("resolveSigningContext: %v", err)
	}
	if apiclient.PrivateKeyFromContext(signedCtx) != nil {
		t.Fatalf("expected NO private key in context when hostRef is explicitly set")
	}

	// 2. hostID is empty AND hostRef is nil -> SHOULD pick up defaultPrivKey
	signedCtxDefault, err := resolveSigningContext(ctx, cl, "default", nil, "", "", nil, staticProvider)
	if err != nil {
		t.Fatalf("resolveSigningContext: %v", err)
	}
	if !apiclient.PrivateKeyFromContext(signedCtxDefault).Equal(defaultPriv) {
		t.Fatalf("expected default private key in context when relying on cluster default host")
	}
}

func TestReconcilerDefaultHostProviderNilSafety(t *testing.T) {
	var typedNilBootstrapper *ClusterHostBootstrapper
	var untypedNilProvider DefaultHostProvider = typedNilBootstrapper

	reqReconciler := &GrantoryRequestReconciler{
		DefaultHostProvider: untypedNilProvider,
	}
	if id, key := reqReconciler.DefaultHostProvider.GetDefaultHost(); id != "" || key != nil {
		t.Fatalf("expected empty id and nil key from typed nil bootstrapper")
	}

	regReconciler := &GrantoryRegisterReconciler{
		DefaultHostProvider: untypedNilProvider,
	}
	if id, key := regReconciler.DefaultHostProvider.GetDefaultHost(); id != "" || key != nil {
		t.Fatalf("expected empty id and nil key from typed nil bootstrapper")
	}
}

func TestHostReconcileRejectsImmutableGrantoryHostIDChange(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/hosts/host-original" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":         "host-original",
				"unique_key": "host-key",
				"labels":     map[string]string{},
			})
			return
		}
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	host := &v1alpha1.GrantoryHost{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "host-test",
			Namespace:  "default",
			Finalizers: []string{grantoryFinalizer},
		},
		Spec: v1alpha1.GrantoryHostSpec{
			GrantoryHostID: "host-changed",
		},
		Status: v1alpha1.GrantoryHostStatus{
			ID: "host-original",
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryHost{}).
		WithObjects(host).
		Build()

	reconciler := &GrantoryHostReconciler{
		Client:         cl,
		Scheme:         scheme,
		GrantoryClient: clienttest.New(t, server, "", "", ""),
	}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "host-test", Namespace: "default"}})
	if err == nil {
		t.Fatalf("expected error when changing grantoryHostID on existing host, got nil")
	}

	var updated v1alpha1.GrantoryHost
	if err := cl.Get(ctx, types.NamespacedName{Name: "host-test", Namespace: "default"}, &updated); err != nil {
		t.Fatalf("get host: %v", err)
	}
	cond := meta.FindStatusCondition(updated.Status.Conditions, "Ready")
	if cond == nil || cond.Reason != "ImmutableFieldChanged" {
		t.Fatalf("expected condition reason ImmutableFieldChanged, got %v", cond)
	}
}

func TestResolveHostIDEmptyHostRefName(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)
	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	_, _, err := resolveHostID(ctx, cl, "default", "", &v1alpha1.HostRef{Name: ""}, "default-host-id")
	if err == nil {
		t.Fatalf("expected error for empty hostRef.name, got nil")
	}
	if !strings.Contains(err.Error(), "hostRef.name cannot be empty") {
		t.Fatalf("expected 'hostRef.name cannot be empty', got: %v", err)
	}

	_, _, err = resolveHostID(ctx, cl, "default", "", &v1alpha1.HostRef{Name: "   "}, "default-host-id")
	if err == nil {
		t.Fatalf("expected error for whitespace hostRef.name, got nil")
	}
}

func TestResolveHostIDCrossNamespaceRejected(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)
	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	_, _, err := resolveHostID(ctx, cl, "tenant-a", "", &v1alpha1.HostRef{Name: "shared-host", Namespace: "tenant-b"}, "default-host-id")
	if err == nil {
		t.Fatalf("expected error for cross-namespace hostRef, got nil")
	}
	if !strings.Contains(err.Error(), "cross-namespace hostRef is not permitted") {
		t.Fatalf("expected 'cross-namespace hostRef is not permitted', got: %v", err)
	}
}

func TestRequestReconcileEmptyHostRefFailsFastWithoutRequeue(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	req := &v1alpha1.GrantoryRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "req-bad-ref",
			Namespace:  "default",
			Finalizers: []string{grantoryFinalizer},
		},
		Spec: v1alpha1.GrantoryRequestSpec{
			HostRef: &v1alpha1.HostRef{Name: ""},
			Payload: runtime.RawExtension{Raw: []byte(`{"action":"login"}`)},
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryRequest{}).
		WithObjects(req).
		Build()

	notReadyBootstrapper := NewClusterHostBootstrapper(cl, cl, nil, ClusterHostOptions{})

	reconciler := &GrantoryRequestReconciler{
		Client:              cl,
		Scheme:              scheme,
		DefaultHostProvider: notReadyBootstrapper,
	}

	res, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "req-bad-ref", Namespace: "default"}})
	if err == nil {
		t.Fatalf("expected error for empty hostRef.name, got nil")
	}
	if res.RequeueAfter != 0 {
		t.Fatalf("expected no requeue for invalid hostRef, got %v", res.RequeueAfter)
	}

	var updated v1alpha1.GrantoryRequest
	if err := cl.Get(ctx, types.NamespacedName{Name: "req-bad-ref", Namespace: "default"}, &updated); err != nil {
		t.Fatalf("get request: %v", err)
	}
	cond := meta.FindStatusCondition(updated.Status.Conditions, "Ready")
	if cond == nil || cond.Reason != "InvalidHost" {
		t.Fatalf("expected condition reason InvalidHost, got %v", cond)
	}
}

func TestRegisterReconcileEmptyHostRefFailsFastWithoutRequeue(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	reg := &v1alpha1.GrantoryRegister{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "reg-bad-ref",
			Namespace:  "default",
			Finalizers: []string{grantoryFinalizer},
		},
		Spec: v1alpha1.GrantoryRegisterSpec{
			HostRef: &v1alpha1.HostRef{Name: ""},
			Payload: runtime.RawExtension{Raw: []byte(`{"service":"db"}`)},
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryRegister{}).
		WithObjects(reg).
		Build()

	notReadyBootstrapper := NewClusterHostBootstrapper(cl, cl, nil, ClusterHostOptions{})

	reconciler := &GrantoryRegisterReconciler{
		Client:              cl,
		Scheme:              scheme,
		DefaultHostProvider: notReadyBootstrapper,
	}

	res, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "reg-bad-ref", Namespace: "default"}})
	if err == nil {
		t.Fatalf("expected error for empty hostRef.name, got nil")
	}
	if res.RequeueAfter != 0 {
		t.Fatalf("expected no requeue for invalid hostRef, got %v", res.RequeueAfter)
	}

	var updated v1alpha1.GrantoryRegister
	if err := cl.Get(ctx, types.NamespacedName{Name: "reg-bad-ref", Namespace: "default"}, &updated); err != nil {
		t.Fatalf("get register: %v", err)
	}
	cond := meta.FindStatusCondition(updated.Status.Conditions, "Ready")
	if cond == nil || cond.Reason != "InvalidHost" {
		t.Fatalf("expected condition reason InvalidHost, got %v", cond)
	}
}

func TestRequestReconcileRejectsImmutableHostChange(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/requests/req-1" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":         "req-1",
				"host_id":    "host-original",
				"payload":    map[string]any{"action": "login"},
				"labels":     map[string]string{},
				"created_at": "2026-03-29T00:00:00Z",
				"updated_at": "2026-03-29T00:00:00Z",
			})
			return
		}
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	req := &v1alpha1.GrantoryRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "req-imm-host",
			Namespace:  "default",
			Finalizers: []string{grantoryFinalizer},
		},
		Spec: v1alpha1.GrantoryRequestSpec{
			HostID:  "host-changed",
			Payload: runtime.RawExtension{Raw: []byte(`{"action":"login"}`)},
		},
		Status: v1alpha1.GrantoryRequestStatus{
			ID: "req-1",
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryRequest{}).
		WithObjects(req).
		Build()

	reconciler := &GrantoryRequestReconciler{
		Client:         cl,
		Scheme:         scheme,
		GrantoryClient: clienttest.New(t, server, "", "", ""),
	}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "req-imm-host", Namespace: "default"}})
	if err == nil {
		t.Fatalf("expected error when mutating host on existing request, got nil")
	}

	var updated v1alpha1.GrantoryRequest
	if err := cl.Get(ctx, types.NamespacedName{Name: "req-imm-host", Namespace: "default"}, &updated); err != nil {
		t.Fatalf("get request: %v", err)
	}
	cond := meta.FindStatusCondition(updated.Status.Conditions, "Ready")
	if cond == nil || cond.Reason != "ImmutableFieldChanged" {
		t.Fatalf("expected condition reason ImmutableFieldChanged, got %v", cond)
	}
}

func TestRegisterReconcileRejectsImmutableHostChange(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/registers/reg-1" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":         "reg-1",
				"host_id":    "host-original",
				"payload":    map[string]any{"service": "db"},
				"labels":     map[string]string{},
				"created_at": "2026-03-29T00:00:00Z",
				"updated_at": "2026-03-29T00:00:00Z",
			})
			return
		}
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	reg := &v1alpha1.GrantoryRegister{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "reg-imm-host",
			Namespace:  "default",
			Finalizers: []string{grantoryFinalizer},
		},
		Spec: v1alpha1.GrantoryRegisterSpec{
			HostID:  "host-changed",
			Payload: runtime.RawExtension{Raw: []byte(`{"service":"db"}`)},
		},
		Status: v1alpha1.GrantoryRegisterStatus{
			ID: "reg-1",
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryRegister{}).
		WithObjects(reg).
		Build()

	reconciler := &GrantoryRegisterReconciler{
		Client:         cl,
		Scheme:         scheme,
		GrantoryClient: clienttest.New(t, server, "", "", ""),
	}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "reg-imm-host", Namespace: "default"}})
	if err == nil {
		t.Fatalf("expected error when mutating host on existing register, got nil")
	}

	var updated v1alpha1.GrantoryRegister
	if err := cl.Get(ctx, types.NamespacedName{Name: "reg-imm-host", Namespace: "default"}, &updated); err != nil {
		t.Fatalf("get register: %v", err)
	}
	cond := meta.FindStatusCondition(updated.Status.Conditions, "Ready")
	if cond == nil || cond.Reason != "ImmutableFieldChanged" {
		t.Fatalf("expected condition reason ImmutableFieldChanged, got %v", cond)
	}
}

func TestRequestReconcileForceRemoveFinalizerAnnotation(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)
	now := metav1.Now()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("server should not be called when force-remove-finalizer annotation is set: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	req := &v1alpha1.GrantoryRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "req-force-del",
			Namespace:         "default",
			DeletionTimestamp: &now,
			Finalizers:        []string{grantoryFinalizer},
			Annotations: map[string]string{
				ForceRemoveFinalizerAnnotation: "true",
			},
		},
		Status: v1alpha1.GrantoryRequestStatus{
			ID: "req-1",
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryRequest{}).
		WithObjects(req).
		Build()

	reconciler := &GrantoryRequestReconciler{
		Client:         cl,
		Scheme:         scheme,
		GrantoryClient: clienttest.New(t, server, "", "", ""),
	}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "req-force-del", Namespace: "default"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var updated v1alpha1.GrantoryRequest
	err = cl.Get(ctx, types.NamespacedName{Name: "req-force-del", Namespace: "default"}, &updated)
	if err == nil && len(updated.Finalizers) != 0 {
		t.Fatalf("expected object to be deleted or finalizers removed, got %v", updated.Finalizers)
	}
	if err != nil && !apierrors.IsNotFound(err) {
		t.Fatalf("unexpected get error: %v", err)
	}
}

func TestRegisterReconcileForceRemoveFinalizerAnnotation(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)
	now := metav1.Now()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("server should not be called when force-remove-finalizer annotation is set: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	reg := &v1alpha1.GrantoryRegister{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "reg-force-del",
			Namespace:         "default",
			DeletionTimestamp: &now,
			Finalizers:        []string{grantoryFinalizer},
			Annotations: map[string]string{
				ForceRemoveFinalizerAnnotation: "true",
			},
		},
		Status: v1alpha1.GrantoryRegisterStatus{
			ID: "reg-1",
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryRegister{}).
		WithObjects(reg).
		Build()

	reconciler := &GrantoryRegisterReconciler{
		Client:         cl,
		Scheme:         scheme,
		GrantoryClient: clienttest.New(t, server, "", "", ""),
	}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "reg-force-del", Namespace: "default"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var updated v1alpha1.GrantoryRegister
	err = cl.Get(ctx, types.NamespacedName{Name: "reg-force-del", Namespace: "default"}, &updated)
	if err == nil && len(updated.Finalizers) != 0 {
		t.Fatalf("expected object to be deleted or finalizers removed, got %v", updated.Finalizers)
	}
	if err != nil && !apierrors.IsNotFound(err) {
		t.Fatalf("unexpected get error: %v", err)
	}
}

func TestRequestReconcileDoesNotDeleteUnownedSecretOnMissingGrant(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	unownedSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pre-existing-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"password": []byte("supersecret"),
		},
	}

	request := &v1alpha1.GrantoryRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "req-unowned",
			Namespace:  "default",
			UID:        types.UID("req-uid-unowned"),
			Finalizers: []string{grantoryFinalizer},
		},
		Spec: v1alpha1.GrantoryRequestSpec{
			HostID:          "host-1",
			GrantOutputKind: "secret",
			GrantOutputName: "pre-existing-secret",
			Payload:         runtime.RawExtension{Raw: []byte(`{"action":"read"}`)},
		},
		Status: v1alpha1.GrantoryRequestStatus{
			ID: "req-1",
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/requests/req-1" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":        "req-1",
				"host_id":   "host-1",
				"payload":   map[string]any{"action": "read"},
				"has_grant": false,
			})
			return
		}
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryRequest{}).
		WithObjects(unownedSecret, request).
		Build()

	reconciler := &GrantoryRequestReconciler{
		Client:         cl,
		Scheme:         scheme,
		GrantoryClient: clienttest.New(t, server, "", "", ""),
	}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "req-unowned", Namespace: "default"}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var secretAfter corev1.Secret
	if err := cl.Get(ctx, types.NamespacedName{Name: "pre-existing-secret", Namespace: "default"}, &secretAfter); err != nil {
		t.Fatalf("expected pre-existing unowned secret to still exist, but got: %v", err)
	}
	if string(secretAfter.Data["password"]) != "supersecret" {
		t.Fatalf("expected password data intact, got %s", string(secretAfter.Data["password"]))
	}
}

func TestRequestReconcileRedactsGrantPayloadForSecret(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	request := &v1alpha1.GrantoryRequest{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "GrantoryRequest",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "req-secret-output",
			Namespace:  "default",
			UID:        types.UID("req-uid-secret"),
			Finalizers: []string{grantoryFinalizer},
		},
		Spec: v1alpha1.GrantoryRequestSpec{
			HostID:          "host-1",
			GrantOutputKind: "secret",
			GrantOutputName: "req-secret",
			GrantOutputKeys: map[string]string{
				"/token": "token",
			},
		},
		Status: v1alpha1.GrantoryRequestStatus{
			ID: "req-1",
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/requests/req-1" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":        "req-1",
			"host_id":   "host-1",
			"has_grant": true,
			"grant": map[string]any{
				"grant_id":   "grant-1",
				"created_at": "2026-03-10T10:00:00Z",
				"updated_at": "2026-03-10T10:00:00Z",
				"payload": map[string]any{
					"token": "sensitive-token-123",
				},
			},
		})
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryRequest{}).
		WithObjects(request).
		Build()

	reconciler := &GrantoryRequestReconciler{
		Client:         cl,
		Scheme:         scheme,
		GrantoryClient: clienttest.New(t, server, "", "", ""),
	}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "req-secret-output", Namespace: "default"}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var secret corev1.Secret
	if err := cl.Get(ctx, types.NamespacedName{Name: "req-secret", Namespace: "default"}, &secret); err != nil {
		t.Fatalf("expected secret to be created: %v", err)
	}
	if string(secret.Data["token"]) != "sensitive-token-123" {
		t.Fatalf("expected secret token to match, got %s", string(secret.Data["token"]))
	}

	var updated v1alpha1.GrantoryRequest
	if err := cl.Get(ctx, types.NamespacedName{Name: "req-secret-output", Namespace: "default"}, &updated); err != nil {
		t.Fatalf("get request: %v", err)
	}
	if len(updated.Status.GrantPayload.Raw) != 0 {
		t.Fatalf("expected status.GrantPayload to be redacted when grantOutputKind=secret, but got: %s", string(updated.Status.GrantPayload.Raw))
	}
}

func TestRequestReconcileClearsGrantStatusOnRecreation(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	request := &v1alpha1.GrantoryRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "req-recreate-grant",
			Namespace:  "default",
			UID:        types.UID("req-uid-recreate"),
			Finalizers: []string{grantoryFinalizer},
		},
		Spec: v1alpha1.GrantoryRequestSpec{
			HostID:  "host-1",
			Payload: runtime.RawExtension{Raw: []byte(`{"version":2}`)},
		},
		Status: v1alpha1.GrantoryRequestStatus{
			ID:           "req-1",
			HasGrant:     true,
			GrantID:      "grant-1",
			GrantPayload: runtime.RawExtension{Raw: []byte(`{"token":"old-token"}`)},
		},
	}

	deleted := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/requests/req-1" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":        "req-1",
				"host_id":   "host-1",
				"payload":   map[string]any{"version": float64(1)},
				"has_grant": true,
			})
			return
		}
		if r.Method == http.MethodDelete && r.URL.Path == "/requests/req-1" {
			deleted = true
			w.WriteHeader(http.StatusNoContent)
			return
		}
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryRequest{}).
		WithObjects(request).
		Build()

	reconciler := &GrantoryRequestReconciler{
		Client:         cl,
		Scheme:         scheme,
		GrantoryClient: clienttest.New(t, server, "", "", ""),
	}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "req-recreate-grant", Namespace: "default"}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if !deleted {
		t.Fatalf("expected remote request to be deleted")
	}

	var updated v1alpha1.GrantoryRequest
	if err := cl.Get(ctx, types.NamespacedName{Name: "req-recreate-grant", Namespace: "default"}, &updated); err != nil {
		t.Fatalf("get request: %v", err)
	}
	if updated.Status.ID != "" {
		t.Fatalf("expected status.ID to be empty, got %q", updated.Status.ID)
	}
	if updated.Status.HasGrant {
		t.Fatalf("expected status.HasGrant to be false upon recreation")
	}
	if updated.Status.GrantID != "" {
		t.Fatalf("expected status.GrantID to be empty upon recreation, got %q", updated.Status.GrantID)
	}
	if len(updated.Status.GrantPayload.Raw) != 0 {
		t.Fatalf("expected status.GrantPayload to be cleared upon recreation")
	}
}

func TestHostReconcileAdoptedHostPreservesRemoteLabelsWhenUnset(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	host := &v1alpha1.GrantoryHost{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "GrantoryHost",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "adopted-preserve-labels",
			Namespace: "default",
		},
		Spec: v1alpha1.GrantoryHostSpec{
			GrantoryHostID: "host-remote-123",
			// Labels is intentionally nil
		},
	}

	var patchLabelsCalled atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/hosts/host-remote-123":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":     "host-remote-123",
				"labels": map[string]string{"env": "production", "team": "infra"},
			})
		case r.Method == http.MethodPatch && r.URL.Path == "/hosts/host-remote-123/labels":
			patchLabelsCalled.Store(true)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "host-remote-123"})
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryHost{}).
		WithObjects(host).
		Build()

	reconciler := &GrantoryHostReconciler{
		Client:         cl,
		Scheme:         scheme,
		GrantoryClient: clienttest.New(t, server, "", "", ""),
	}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "adopted-preserve-labels", Namespace: "default"}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if patchLabelsCalled.Load() {
		t.Fatalf("expected remote labels to be preserved when host.Spec.Labels is nil, but UpdateHostLabels was called")
	}
}

func TestRequestReconcileSignedDeletionWithHostRefToDefaultHost(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	var hasSig atomic.Bool
	var deleteCalled atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && r.URL.Path == "/requests/req-hostref-del" {
			deleteCalled.Store(true)
			if r.Header.Get("X-Grantory-Signature") != "" && r.Header.Get("X-Grantory-Timestamp") != "" {
				hasSig.Store(true)
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	clusterHost := &v1alpha1.GrantoryHost{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cluster-host",
			Namespace: "default",
		},
		Status: v1alpha1.GrantoryHostStatus{
			ID: "cluster-host-id",
		},
	}

	now := metav1.Now()
	request := &v1alpha1.GrantoryRequest{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "GrantoryRequest",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:              "req-hostref-del",
			Namespace:         "default",
			Finalizers:        []string{grantoryFinalizer},
			DeletionTimestamp: &now,
		},
		Spec: v1alpha1.GrantoryRequestSpec{
			HostRef: &v1alpha1.HostRef{
				Name: "cluster-host",
			},
		},
		Status: v1alpha1.GrantoryRequestStatus{
			ID: "req-hostref-del",
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryRequest{}).
		WithObjects(clusterHost, request).
		Build()

	staticProvider := StaticHostProvider{
		HostID:     "cluster-host-id",
		PrivateKey: priv,
	}

	reconciler := &GrantoryRequestReconciler{
		Client:              cl,
		Scheme:              scheme,
		GrantoryClient:      clienttest.New(t, server, "", "", ""),
		DefaultHostProvider: staticProvider,
	}

	_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "req-hostref-del", Namespace: "default"}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if !deleteCalled.Load() {
		t.Fatalf("expected DELETE /requests/req-hostref-del to be called")
	}
	if !hasSig.Load() {
		t.Fatalf("expected DELETE /requests/req-hostref-del to be signed using default cluster host key when HostRef points to cluster host")
	}
}

func TestRegisterReconcileSignedDeletionWithHostRefToDefaultHost(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	var hasSig atomic.Bool
	var deleteCalled atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && r.URL.Path == "/registers/reg-hostref-del" {
			deleteCalled.Store(true)
			if r.Header.Get("X-Grantory-Signature") != "" && r.Header.Get("X-Grantory-Timestamp") != "" {
				hasSig.Store(true)
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	clusterHost := &v1alpha1.GrantoryHost{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cluster-host",
			Namespace: "default",
		},
		Status: v1alpha1.GrantoryHostStatus{
			ID: "cluster-host-id",
		},
	}

	now := metav1.Now()
	register := &v1alpha1.GrantoryRegister{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "GrantoryRegister",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:              "reg-hostref-del",
			Namespace:         "default",
			Finalizers:        []string{grantoryFinalizer},
			DeletionTimestamp: &now,
		},
		Spec: v1alpha1.GrantoryRegisterSpec{
			HostRef: &v1alpha1.HostRef{
				Name: "cluster-host",
			},
		},
		Status: v1alpha1.GrantoryRegisterStatus{
			ID: "reg-hostref-del",
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryRegister{}).
		WithObjects(clusterHost, register).
		Build()

	staticProvider := StaticHostProvider{
		HostID:     "cluster-host-id",
		PrivateKey: priv,
	}

	reconciler := &GrantoryRegisterReconciler{
		Client:              cl,
		Scheme:              scheme,
		GrantoryClient:      clienttest.New(t, server, "", "", ""),
		DefaultHostProvider: staticProvider,
	}

	_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "reg-hostref-del", Namespace: "default"}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if !deleteCalled.Load() {
		t.Fatalf("expected DELETE /registers/reg-hostref-del to be called")
	}
	if !hasSig.Load() {
		t.Fatalf("expected DELETE /registers/reg-hostref-del to be signed using default cluster host key when HostRef points to cluster host")
	}
}

func TestFinalizerRemovedWhenDeleteOnRemovalToggledFalse(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	falseVal := false
	host := &v1alpha1.GrantoryHost{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "GrantoryHost",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "host-toggle-finalizer",
			Namespace:  "default",
			Finalizers: []string{grantoryFinalizer},
		},
		Spec: v1alpha1.GrantoryHostSpec{
			GrantoryHostID:  "host-remote-123",
			DeleteOnRemoval: &falseVal,
		},
		Status: v1alpha1.GrantoryHostStatus{
			ID: "host-remote-123",
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/hosts/host-remote-123" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "host-remote-123"})
			return
		}
		t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryHost{}).
		WithObjects(host).
		Build()

	reconciler := &GrantoryHostReconciler{
		Client:         cl,
		Scheme:         scheme,
		GrantoryClient: clienttest.New(t, server, "", "", ""),
	}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "host-toggle-finalizer", Namespace: "default"}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var updated v1alpha1.GrantoryHost
	if err := cl.Get(ctx, types.NamespacedName{Name: "host-toggle-finalizer", Namespace: "default"}, &updated); err != nil {
		t.Fatalf("get host: %v", err)
	}
	if len(updated.Finalizers) != 0 {
		t.Fatalf("expected finalizers to be removed when DeleteOnRemoval is toggled to false, got %v", updated.Finalizers)
	}
}

func TestHostAdoptedNeverDeletedRemotelyWhenCRDeleted(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	var deleteCalled atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deleteCalled.Store(true)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	delTrue := true
	now := metav1.Now()
	host := &v1alpha1.GrantoryHost{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "GrantoryHost",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:              "adopted-del-test",
			Namespace:         "default",
			Finalizers:        []string{grantoryFinalizer},
			DeletionTimestamp: &now,
		},
		Spec: v1alpha1.GrantoryHostSpec{
			GrantoryHostID:  "remote-critical-host",
			DeleteOnRemoval: &delTrue,
		},
		Status: v1alpha1.GrantoryHostStatus{
			ID: "remote-critical-host",
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryHost{}).
		WithObjects(host).
		Build()

	reconciler := &GrantoryHostReconciler{
		Client:         cl,
		Scheme:         scheme,
		GrantoryClient: clienttest.New(t, server, "", "", ""),
	}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "adopted-del-test", Namespace: "default"}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if deleteCalled.Load() {
		t.Fatalf("adopted host must NEVER trigger remote host deletion on Grantory server")
	}

	var updated v1alpha1.GrantoryHost
	if err := cl.Get(ctx, types.NamespacedName{Name: "adopted-del-test", Namespace: "default"}, &updated); err == nil {
		if len(updated.Finalizers) != 0 {
			t.Fatalf("expected finalizers to be removed, got %v", updated.Finalizers)
		}
	}
}

func TestRequestReconcileRejectsOverwritingUnownedSecret(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	// An existing unowned secret with confidential data
	existingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "target-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"important": []byte("do-not-overwrite"),
		},
	}

	request := &v1alpha1.GrantoryRequest{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "GrantoryRequest",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "hijack-request",
			Namespace:  "default",
			UID:        types.UID("request-uid-123"),
			Finalizers: []string{grantoryFinalizer},
		},
		Spec: v1alpha1.GrantoryRequestSpec{
			HostID:          "host-1",
			GrantOutputKind: "secret",
			GrantOutputName: "target-secret",
		},
		Status: v1alpha1.GrantoryRequestStatus{
			ID: "req-1",
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/requests/req-1" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":        "req-1",
				"host_id":   "host-1",
				"has_grant": true,
				"grant":     map[string]any{"token": "hijacked-token"},
			})
			return
		}
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryRequest{}).
		WithObjects(existingSecret, request).
		Build()

	reconciler := &GrantoryRequestReconciler{
		Client:         cl,
		Scheme:         scheme,
		GrantoryClient: clienttest.New(t, server, "", "", ""),
	}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "hijack-request", Namespace: "default"}})
	if err == nil {
		t.Fatalf("expected error when target secret already exists and is not owned by this request, got nil")
	}

	// Verify original secret data was NOT overwritten
	var sec corev1.Secret
	if err := cl.Get(ctx, types.NamespacedName{Name: "target-secret", Namespace: "default"}, &sec); err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if string(sec.Data["important"]) != "do-not-overwrite" {
		t.Fatalf("expected original secret data to be preserved, got %s", sec.Data["important"])
	}
}

func TestRequestReconcileRejectsOverwritingUnownedConfigMap(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)

	// An existing unowned configmap
	existingConfig := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "target-config",
			Namespace: "default",
		},
		Data: map[string]string{
			"config.json": `{"original": true}`,
		},
	}

	request := &v1alpha1.GrantoryRequest{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "GrantoryRequest",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "hijack-request-cm",
			Namespace:  "default",
			UID:        types.UID("request-uid-456"),
			Finalizers: []string{grantoryFinalizer},
		},
		Spec: v1alpha1.GrantoryRequestSpec{
			HostID:          "host-1",
			GrantOutputKind: "configmap",
			GrantOutputName: "target-config",
		},
		Status: v1alpha1.GrantoryRequestStatus{
			ID: "req-1",
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/requests/req-1" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":        "req-1",
				"host_id":   "host-1",
				"has_grant": true,
				"grant":     map[string]any{"data": "hijacked-data"},
			})
			return
		}
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.GrantoryRequest{}).
		WithObjects(existingConfig, request).
		Build()

	reconciler := &GrantoryRequestReconciler{
		Client:         cl,
		Scheme:         scheme,
		GrantoryClient: clienttest.New(t, server, "", "", ""),
	}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "hijack-request-cm", Namespace: "default"}})
	if err == nil {
		t.Fatalf("expected error when target configmap already exists and is not owned by this request, got nil")
	}

	// Verify original configmap data was NOT overwritten
	var cm corev1.ConfigMap
	if err := cl.Get(ctx, types.NamespacedName{Name: "target-config", Namespace: "default"}, &cm); err != nil {
		t.Fatalf("get configmap: %v", err)
	}
	if cm.Data["config.json"] != `{"original": true}` {
		t.Fatalf("expected original configmap data to be preserved, got %s", cm.Data["config.json"])
	}
}
