package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

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
			Name:      "req",
			Namespace: "default",
			UID:       types.UID("req-uid"),
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
		if r.Method != http.MethodPatch || r.URL.Path != "/requests/req-1" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		labels := decodeLabels(t, r)
		if len(labels) != 0 {
			t.Fatalf("expected empty labels, got %v", labels)
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
			Name:      "req",
			Namespace: "default",
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
			Name:      "req",
			Namespace: "default",
		},
		Spec: v1alpha1.GrantoryRequestSpec{
			HostID:  "host-1",
			Payload: runtime.RawExtension{Raw: []byte(`{"token":"new"}`)},
		},
		Status: v1alpha1.GrantoryRequestStatus{
			ID: "req-1",
		},
	}

	var sawPatch atomic.Bool
	var sawDelete atomic.Bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPatch && r.URL.Path == "/requests/req-1":
			sawPatch.Store(true)
			_ = decodeLabels(t, r)
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
	if !sawPatch.Load() || !sawDelete.Load() {
		t.Fatalf("expected patch and delete, got patch=%v delete=%v", sawPatch.Load(), sawDelete.Load())
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
			Name:      "req",
			Namespace: "default",
			UID:       types.UID("req-uid"),
		},
		Spec: v1alpha1.GrantoryRequestSpec{
			HostID: "host-1",
		},
		Status: v1alpha1.GrantoryRequestStatus{
			ID: "req-1",
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || r.URL.Path != "/requests/req-1" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		_ = decodeLabels(t, r)
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
			Name:      "req",
			Namespace: "default",
			UID:       types.UID("req-uid"),
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
		if r.Method != http.MethodPatch || r.URL.Path != "/requests/req-1" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		labels := decodeLabels(t, r)
		if len(labels) != 0 {
			t.Fatalf("expected empty labels, got %v", labels)
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
			Name:      "req",
			Namespace: "default",
			UID:       types.UID("req-uid"),
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
		if r.Method != http.MethodPatch || r.URL.Path != "/requests/req-1" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		labels := decodeLabels(t, r)
		if len(labels) != 0 {
			t.Fatalf("expected empty labels, got %v", labels)
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
			Name:      "req",
			Namespace: "default",
			UID:       types.UID("req-uid"),
		},
		Spec: v1alpha1.GrantoryRequestSpec{
			HostID:          "host-1",
			GrantOutputKind: "secret",
			GrantOutputKeys: map[string]string{
				"/token": "token",
			},
		},
		Status: v1alpha1.GrantoryRequestStatus{
			ID: "req-1",
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || r.URL.Path != "/requests/req-1" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		labels := decodeLabels(t, r)
		if len(labels) != 0 {
			t.Fatalf("expected empty labels, got %v", labels)
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

	var secret corev1.Secret
	if err := cl.Get(ctx, types.NamespacedName{Name: "req", Namespace: "default"}, &secret); err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if got := string(secret.Data["token"]); got != "abc" {
		t.Fatalf("expected secret token=abc, got %q", got)
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
		case r.Method == http.MethodPatch && r.URL.Path == "/hosts/host-remote/labels":
			labels := decodeLabels(t, r)
			if len(labels) != 0 {
				t.Fatalf("expected empty labels, got %v", labels)
			}
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
			Name:      "host",
			Namespace: "default",
		},
		Status: v1alpha1.GrantoryHostStatus{
			ID: "gone",
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || r.URL.Path != "/hosts/gone/labels" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		_ = decodeLabels(t, r)
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
			Name:      "reg",
			Namespace: "default",
		},
		Spec: v1alpha1.GrantoryRegisterSpec{
			HostID: "host-1",
		},
		Status: v1alpha1.GrantoryRegisterStatus{
			ID: "gone",
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || r.URL.Path != "/registers/gone" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		_ = decodeLabels(t, r)
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

type labelsPayload struct {
	Labels map[string]string `json:"labels"`
}

func decodeLabels(t *testing.T, r *http.Request) map[string]string {
	t.Helper()
	var payload labelsPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		t.Fatalf("decode labels payload: %v", err)
	}
	if payload.Labels == nil {
		payload.Labels = map[string]string{}
	}
	return payload.Labels
}

func hasConditionReason(conditions []metav1.Condition, reason string) bool {
	for _, condition := range conditions {
		if condition.Reason == reason {
			return true
		}
	}
	return false
}
