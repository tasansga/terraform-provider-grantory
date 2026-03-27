package controller

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	apiclient "github.com/tasansga/terraform-provider-grantory/api/client"
	"github.com/tasansga/terraform-provider-grantory/internal/k8s/api/v1alpha1"
)

type GrantoryRegisterReconciler struct {
	client.Client
	Scheme            *runtime.Scheme
	Recorder          record.EventRecorder
	GrantoryClient    *apiclient.Client
	GrantoryNamespace string
}

func (r *GrantoryRegisterReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var register v1alpha1.GrantoryRegister
	if err := r.Get(ctx, req.NamespacedName, &register); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if register.DeletionTimestamp != nil {
		if register.Spec.DeleteOnRemoval && register.Status.ID != "" {
			if err := r.GrantoryClient.DeleteRegister(ctx, register.Status.ID); err != nil {
				if apiclient.IsNotFound(err) {
					// Already deleted.
				} else {
					return ctrl.Result{}, err
				}
			}
		}
		if removeFinalizer(&register) {
			return ctrl.Result{}, r.Update(ctx, &register)
		}
		return ctrl.Result{}, nil
	}

	if ensureFinalizer(register.Spec.DeleteOnRemoval, &register) {
		return ctrl.Result{}, r.Update(ctx, &register)
	}

	hostID, result, err := resolveHostID(ctx, r.Client, register.Namespace, register.Spec.HostID, register.Spec.HostRef)
	if err != nil {
		status := register.Status
		status.ObservedGeneration = register.Generation
		status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "InvalidHost", err.Error(), register.Generation)
		_ = updateRegisterStatus(ctx, r.Client, &register, status)
		return ctrl.Result{}, err
	}
	if result.Requeue || result.RequeueAfter > 0 {
		status := register.Status
		status.ObservedGeneration = register.Generation
		status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "WaitingForHost", "Waiting for referenced host", register.Generation)
		_ = updateRegisterStatus(ctx, r.Client, &register, status)
		return result, nil
	}

	labels := register.Spec.Labels
	if labels == nil {
		labels = map[string]string{}
	}

	var remoteID string
	if register.Status.ID == "" {
		payload, err := rawExtensionToMap(register.Spec.Payload)
		if err != nil {
			status := register.Status
			status.ObservedGeneration = register.Generation
			status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "InvalidPayload", err.Error(), register.Generation)
			_ = updateRegisterStatus(ctx, r.Client, &register, status)
			return ctrl.Result{}, err
		}
		created, err := r.GrantoryClient.CreateRegister(ctx, apiclient.RegisterCreatePayload{
			HostID:             hostID,
			SchemaDefinitionID: register.Spec.SchemaDefinitionID,
			UniqueKey:          register.Spec.UniqueKey,
			Payload:            payload,
			Labels:             labels,
		})
		if err != nil {
			status := register.Status
			status.ObservedGeneration = register.Generation
			status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "CreateFailed", err.Error(), register.Generation)
			_ = updateRegisterStatus(ctx, r.Client, &register, status)
			if r.Recorder != nil {
				r.Recorder.Event(&register, "Warning", "CreateFailed", err.Error())
			}
			return ctrl.Result{}, err
		}
		remoteID = created.ID
		if r.Recorder != nil {
			r.Recorder.Eventf(&register, "Normal", "Created", "Created Grantory register %s", created.ID)
		}
	} else {
		remoteID = register.Status.ID
		if _, err := r.GrantoryClient.UpdateRegisterLabels(ctx, register.Status.ID, labels); err != nil {
			if apiclient.IsNotFound(err) {
				status := register.Status
				status.ID = ""
				status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "NotFound", "Register not found in Grantory, will recreate", register.Generation)
				_ = updateRegisterStatus(ctx, r.Client, &register, status)
				return ctrl.Result{}, nil
			}
			status := register.Status
			status.ObservedGeneration = register.Generation
			status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "UpdateFailed", err.Error(), register.Generation)
			_ = updateRegisterStatus(ctx, r.Client, &register, status)
			if r.Recorder != nil {
				r.Recorder.Event(&register, "Warning", "UpdateFailed", err.Error())
			}
			return ctrl.Result{}, err
		}
	}

	if remoteID == "" {
		return ctrl.Result{}, fmt.Errorf("grantory register ID missing after reconcile")
	}

	status := register.Status
	status.ID = remoteID
	status.ObservedGeneration = register.Generation
	status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionTrue, "Reconciled", "Register synced to Grantory", register.Generation)
	if err := updateRegisterStatus(ctx, r.Client, &register, status); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *GrantoryRegisterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.GrantoryRegister{}).
		Complete(r)
}
