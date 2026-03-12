package controller

import (
	"context"
	"reflect"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/tasansga/terraform-provider-grantory/internal/k8s/api/v1alpha1"
)

func updateHostStatus(ctx context.Context, c client.Client, host *v1alpha1.GrantoryHost, status v1alpha1.GrantoryHostStatus) error {
	if reflect.DeepEqual(host.Status, status) {
		return nil
	}
	updated := host.DeepCopyObject().(*v1alpha1.GrantoryHost)
	updated.Status = status
	return c.Status().Update(ctx, updated)
}

func updateRequestStatus(ctx context.Context, c client.Client, req *v1alpha1.GrantoryRequest, status v1alpha1.GrantoryRequestStatus) error {
	if reflect.DeepEqual(req.Status, status) {
		return nil
	}
	updated := req.DeepCopyObject().(*v1alpha1.GrantoryRequest)
	updated.Status = status
	return c.Status().Update(ctx, updated)
}

func updateRegisterStatus(ctx context.Context, c client.Client, reg *v1alpha1.GrantoryRegister, status v1alpha1.GrantoryRegisterStatus) error {
	if reflect.DeepEqual(reg.Status, status) {
		return nil
	}
	updated := reg.DeepCopyObject().(*v1alpha1.GrantoryRegister)
	updated.Status = status
	return c.Status().Update(ctx, updated)
}
