package controller

import (
	"context"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/tasansga/terraform-provider-grantory/internal/k8s/api/v1alpha1"
)

func resolveHostID(ctx context.Context, c client.Client, namespace, hostID string, hostRef *v1alpha1.HostRef) (string, ctrl.Result, error) {
	if hostID != "" {
		return hostID, ctrl.Result{}, nil
	}
	if hostRef == nil || hostRef.Name == "" {
		return "", ctrl.Result{}, fmt.Errorf("hostID or hostRef.name is required")
	}
	targetNamespace := hostRef.Namespace
	if targetNamespace == "" {
		targetNamespace = namespace
	}
	var host v1alpha1.GrantoryHost
	if err := c.Get(ctx, types.NamespacedName{Name: hostRef.Name, Namespace: targetNamespace}, &host); err != nil {
		if apierrors.IsNotFound(err) {
			return "", ctrl.Result{RequeueAfter: 5 * time.Second}, nil
		}
		return "", ctrl.Result{}, err
	}
	if host.Status.ID == "" {
		return "", ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}
	return host.Status.ID, ctrl.Result{}, nil
}
