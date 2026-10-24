package controller

import (
	"context"
	"fmt"
	"maps"
	"reflect"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	apiclient "github.com/tasansga/terraform-provider-grantory/api/client"
	"github.com/tasansga/terraform-provider-grantory/internal/k8s/api/v1alpha1"
)

type GrantoryRegisterReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	Recorder            events.EventRecorder
	GrantoryClient      *apiclient.Client
	GrantoryNamespace   string
	DefaultHostProvider DefaultHostProvider
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
		if register.Spec.ShouldDeleteOnRemoval() && register.Status.ID != "" && !hasForceRemoveAnnotation(&register) {
			if r.DefaultHostProvider != nil && !r.DefaultHostProvider.IsReady() && register.Spec.HostID == "" && register.Spec.HostRef == nil && register.Spec.PrivateKeySecretRef == nil {
				return ctrl.Result{RequeueAfter: time.Second}, nil
			}
			var defaultHostID string
			if r.DefaultHostProvider != nil {
				if id, _ := r.DefaultHostProvider.GetDefaultHost(); id != "" {
					defaultHostID = id
				}
			}
			hostID, _, _ := resolveHostID(ctx, r.Client, register.Namespace, register.Spec.HostID, register.Spec.HostRef, defaultHostID)
			delCtx, err := resolveSigningContext(ctx, r.Client, register.Namespace, register.Spec.PrivateKeySecretRef, register.Spec.KeyFormat, hostID, register.Spec.HostRef, r.DefaultHostProvider)
			if err != nil && !apierrors.IsNotFound(err) {
				return ctrl.Result{}, err
			}
			secretMissing := err != nil && apierrors.IsNotFound(err)
			if err := r.GrantoryClient.DeleteRegister(delCtx, register.Status.ID); err != nil && !apiclient.IsNotFound(err) {
				if secretMissing && apiclient.IsUnauthorized(err) && r.Recorder != nil {
					r.Recorder.Eventf(&register, nil, "Warning", "SecretNotFoundCannotSignDelete", "Delete", "Signing secret missing; annotate with %s: 'true' to force finalizer removal", ForceRemoveFinalizerAnnotation)
				}
				return ctrl.Result{}, err
			}
		}
		if removeFinalizer(&register) {
			return ctrl.Result{}, r.Update(ctx, &register)
		}
		return ctrl.Result{}, nil
	}

	if syncFinalizer(register.Spec.ShouldDeleteOnRemoval(), &register) {
		return ctrl.Result{}, r.Update(ctx, &register)
	}

	var defaultHostID string
	if r.DefaultHostProvider != nil {
		if id, _ := r.DefaultHostProvider.GetDefaultHost(); id != "" {
			defaultHostID = id
		}
	}

	hostID, result, err := resolveHostID(ctx, r.Client, register.Namespace, register.Spec.HostID, register.Spec.HostRef, defaultHostID)
	if err != nil {
		if r.DefaultHostProvider != nil && register.Spec.HostID == "" && register.Spec.HostRef == nil {
			return ctrl.Result{RequeueAfter: time.Second}, nil
		}
		status := register.Status
		status.ObservedGeneration = register.Generation
		status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "InvalidHost", err.Error(), register.Generation)
		_ = updateRegisterStatus(ctx, r.Client, &register, status)
		return ctrl.Result{}, err
	}
	if result.RequeueAfter > 0 {
		status := register.Status
		status.ObservedGeneration = register.Generation
		status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "WaitingForHost", "Waiting for referenced host", register.Generation)
		_ = updateRegisterStatus(ctx, r.Client, &register, status)
		return result, nil
	}

	ctx, err = resolveSigningContext(ctx, r.Client, register.Namespace, register.Spec.PrivateKeySecretRef, register.Spec.KeyFormat, hostID, register.Spec.HostRef, r.DefaultHostProvider)
	if err != nil {
		if apierrors.IsNotFound(err) && register.Spec.PrivateKeySecretRef != nil {
			status := register.Status
			status.ObservedGeneration = register.Generation
			status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "WaitingForSecret", fmt.Sprintf("Waiting for referenced secret %s", register.Spec.PrivateKeySecretRef.Name), register.Generation)
			_ = updateRegisterStatus(ctx, r.Client, &register, status)
			return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
		}
		status := register.Status
		status.ObservedGeneration = register.Generation
		status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "InvalidPrivateKey", err.Error(), register.Generation)
		_ = updateRegisterStatus(ctx, r.Client, &register, status)
		return ctrl.Result{}, err
	}

	labels := register.Spec.Labels
	if labels == nil {
		labels = map[string]string{}
	}

	desiredPayload, err := parsePayloadString(register.Spec.Payload)
	if err != nil {
		status := register.Status
		status.ObservedGeneration = register.Generation
		status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "InvalidPayload", err.Error(), register.Generation)
		_ = updateRegisterStatus(ctx, r.Client, &register, status)
		return ctrl.Result{}, err
	}

	var remoteID string
	if register.Status.ID == "" {
		created, err := r.GrantoryClient.CreateRegister(ctx, apiclient.RegisterCreatePayload{
			HostID:             hostID,
			SchemaDefinitionID: register.Spec.SchemaDefinitionID,
			UniqueKey:          register.Spec.UniqueKey,
			Payload:            desiredPayload,
			Mutable:            register.Spec.Mutable,
			Labels:             labels,
		})
		if err != nil {
			status := register.Status
			status.ObservedGeneration = register.Generation
			status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "CreateFailed", err.Error(), register.Generation)
			_ = updateRegisterStatus(ctx, r.Client, &register, status)
			if r.Recorder != nil {
				r.Recorder.Eventf(&register, nil, "Warning", "CreateFailed", "Create", "%s", err.Error())
			}
			return ctrl.Result{}, err
		}
		remoteID = created.ID
		if r.Recorder != nil {
			r.Recorder.Eventf(&register, nil, "Normal", "Created", "Create", "Created Grantory register %s", created.ID)
		}
	} else {
		existing, err := r.GrantoryClient.GetRegister(ctx, register.Status.ID)
		if err != nil {
			if apiclient.IsNotFound(err) {
				status := register.Status
				status.ID = ""
				status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "NotFound", "Register not found in Grantory, will recreate", register.Generation)
				_ = updateRegisterStatus(ctx, r.Client, &register, status)
				return ctrl.Result{}, nil
			}
			status := register.Status
			status.ObservedGeneration = register.Generation
			status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "GetFailed", err.Error(), register.Generation)
			_ = updateRegisterStatus(ctx, r.Client, &register, status)
			return ctrl.Result{}, err
		}

		if existing.HostID != hostID {
			err := fmt.Errorf("register host identity is immutable on existing register (status=%s, current=%s, spec=%s); recreating is blocked to prevent signature invalidation", register.Status.ID, existing.HostID, hostID)
			status := register.Status
			status.ObservedGeneration = register.Generation
			status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "ImmutableFieldChanged", err.Error(), register.Generation)
			_ = updateRegisterStatus(ctx, r.Client, &register, status)
			if r.Recorder != nil {
				r.Recorder.Eventf(&register, nil, "Warning", "ImmutableFieldChanged", "Update", "%s", err.Error())
			}
			return ctrl.Result{}, err
		}

		immutableFieldChanged := existing.SchemaDefinitionID != register.Spec.SchemaDefinitionID ||
			existing.UniqueKey != register.Spec.UniqueKey ||
			existing.Mutable != register.Spec.Mutable

		payloadChanged := !reflect.DeepEqual(normalizePayload(desiredPayload), normalizePayload(existing.Payload))
		labelsChanged := !maps.Equal(existing.Labels, labels)

		if immutableFieldChanged || (!register.Spec.Mutable && payloadChanged) {
			if err := r.GrantoryClient.DeleteRegister(ctx, existing.ID); err != nil && !apiclient.IsNotFound(err) {
				return ctrl.Result{}, err
			}
			status := register.Status
			status.ID = ""
			status.ObservedGeneration = register.Generation
			status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "SpecChanged", "Register spec changed, recreating", register.Generation)
			_ = updateRegisterStatus(ctx, r.Client, &register, status)
			return ctrl.Result{RequeueAfter: time.Second}, nil
		}

		remoteID = existing.ID
		if register.Spec.Mutable && (payloadChanged || labelsChanged) {
			patchPayload := desiredPayload
			if payloadChanged && patchPayload == nil {
				patchPayload = map[string]any{}
			}
			updated, err := r.GrantoryClient.UpdateRegister(ctx, register.Status.ID, apiclient.RegisterUpdatePayload{
				Payload: patchPayload,
				Labels:  labels,
			})
			if err != nil {
				status := register.Status
				status.ObservedGeneration = register.Generation
				status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "UpdateFailed", err.Error(), register.Generation)
				_ = updateRegisterStatus(ctx, r.Client, &register, status)
				if r.Recorder != nil {
					r.Recorder.Eventf(&register, nil, "Warning", "UpdateFailed", "Update", "%s", err.Error())
				}
				return ctrl.Result{}, err
			}
			remoteID = updated.ID
		} else if labelsChanged {
			updated, err := r.GrantoryClient.UpdateRegisterLabels(ctx, register.Status.ID, labels)
			if err != nil {
				status := register.Status
				status.ObservedGeneration = register.Generation
				status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "UpdateFailed", err.Error(), register.Generation)
				_ = updateRegisterStatus(ctx, r.Client, &register, status)
				if r.Recorder != nil {
					r.Recorder.Eventf(&register, nil, "Warning", "UpdateFailed", "Update", "%s", err.Error())
				}
				return ctrl.Result{}, err
			}
			remoteID = updated.ID
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
