package controller

import (
	"context"
	"fmt"
	"maps"
	"strings"
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

type GrantoryHostReconciler struct {
	client.Client
	Scheme            *runtime.Scheme
	Recorder          events.EventRecorder
	GrantoryClient    *apiclient.Client
	GrantoryNamespace string
}

func (r *GrantoryHostReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var host v1alpha1.GrantoryHost
	if err := r.Get(ctx, req.NamespacedName, &host); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if host.DeletionTimestamp != nil {
		if host.Spec.ShouldDeleteOnRemoval() && host.Status.ID != "" && !hasForceRemoveAnnotation(&host) {
			if err := r.GrantoryClient.DeleteHost(ctx, host.Status.ID); err != nil {
				if apiclient.IsNotFound(err) {
					// Already gone.
				} else {
					return ctrl.Result{}, err
				}
			}
		}
		if removeFinalizer(&host) {
			return ctrl.Result{}, r.Update(ctx, &host)
		}
		return ctrl.Result{}, nil
	}

	if host.Status.ID != "" && host.Spec.GrantoryHostID != "" && host.Status.ID != host.Spec.GrantoryHostID {
		err := fmt.Errorf("host grantoryHostID is immutable on existing host (status=%s, spec=%s); recreating is blocked to prevent cascading deletion", host.Status.ID, host.Spec.GrantoryHostID)
		status := host.Status
		status.ObservedGeneration = host.Generation
		status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "ImmutableFieldChanged", err.Error(), host.Generation)
		_ = updateHostStatus(ctx, r.Client, &host, status)
		if r.Recorder != nil {
			r.Recorder.Eventf(&host, nil, "Warning", "ImmutableFieldChanged", "Update", "%s", err.Error())
		}
		return ctrl.Result{}, err
	}

	if syncFinalizer(host.Spec.ShouldDeleteOnRemoval(), &host) {
		return ctrl.Result{}, r.Update(ctx, &host)
	}

	status := host.Status
	status.ObservedGeneration = host.Generation

	labels := host.Spec.Labels
	if labels == nil {
		labels = map[string]string{}
	}

	var remoteID string
	if host.Status.ID == "" && host.Spec.GrantoryHostID != "" {
		existing, err := r.GrantoryClient.GetHost(ctx, host.Spec.GrantoryHostID)
		if err != nil {
			if apiclient.IsNotFound(err) {
				status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "NotFound", "Grantory host ID not found", host.Generation)
				_ = updateHostStatus(ctx, r.Client, &host, status)
				return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
			}
			return ctrl.Result{}, err
		}
		remoteID = existing.ID
		if host.Spec.Labels != nil && !maps.Equal(existing.Labels, host.Spec.Labels) {
			if _, err := r.GrantoryClient.UpdateHostLabels(ctx, existing.ID, host.Spec.Labels); err != nil {
				status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "UpdateFailed", err.Error(), host.Generation)
				_ = updateHostStatus(ctx, r.Client, &host, status)
				return ctrl.Result{}, err
			}
		}
	} else if host.Status.ID == "" {
		pubKeyHex, err := resolvePublicKeyHex(host.Spec.PublicKey, host.Spec.KeyFormat)
		if err != nil {
			status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "InvalidPublicKey", err.Error(), host.Generation)
			_ = updateHostStatus(ctx, r.Client, &host, status)
			return ctrl.Result{}, err
		}
		created, err := r.GrantoryClient.CreateHost(ctx, apiclient.HostCreatePayload{
			UniqueKey: host.Spec.UniqueKey,
			PublicKey: pubKeyHex,
			Labels:    labels,
		})
		if err != nil {
			status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "CreateFailed", err.Error(), host.Generation)
			_ = updateHostStatus(ctx, r.Client, &host, status)
			if r.Recorder != nil {
				r.Recorder.Eventf(&host, nil, "Warning", "CreateFailed", "Create", "%s", err.Error())
			}
			return ctrl.Result{}, err
		}
		remoteID = created.ID
		if r.Recorder != nil {
			r.Recorder.Eventf(&host, nil, "Normal", "Created", "Create", "Created Grantory host %s", created.ID)
		}
	} else {
		existing, err := r.GrantoryClient.GetHost(ctx, host.Status.ID)
		if err != nil {
			if apiclient.IsNotFound(err) {
				status.ID = ""
				status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "NotFound", "Host not found in Grantory, will recreate", host.Generation)
				_ = updateHostStatus(ctx, r.Client, &host, status)
				return ctrl.Result{}, nil
			}
			status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "GetFailed", err.Error(), host.Generation)
			_ = updateHostStatus(ctx, r.Client, &host, status)
			return ctrl.Result{}, err
		}

		if host.Spec.GrantoryHostID != "" && host.Status.ID != host.Spec.GrantoryHostID {
			err := fmt.Errorf("host grantoryHostID is immutable on existing host (status=%s, spec=%s); recreating is blocked to prevent cascading deletion", host.Status.ID, host.Spec.GrantoryHostID)
			status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "ImmutableFieldChanged", err.Error(), host.Generation)
			_ = updateHostStatus(ctx, r.Client, &host, status)
			if r.Recorder != nil {
				r.Recorder.Eventf(&host, nil, "Warning", "ImmutableFieldChanged", "Update", "%s", err.Error())
			}
			return ctrl.Result{}, err
		}

		if host.Spec.GrantoryHostID == "" {
			pubKeyHex, err := resolvePublicKeyHex(host.Spec.PublicKey, host.Spec.KeyFormat)
			if err != nil {
				status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "InvalidPublicKey", err.Error(), host.Generation)
				_ = updateHostStatus(ctx, r.Client, &host, status)
				return ctrl.Result{}, err
			}

			if existing.UniqueKey != host.Spec.UniqueKey || !strings.EqualFold(existing.PublicKey, pubKeyHex) {
				err := fmt.Errorf("host uniqueKey and publicKey are immutable on existing host %s; recreating is blocked to prevent cascading deletion", existing.ID)
				status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "ImmutableFieldChanged", err.Error(), host.Generation)
				_ = updateHostStatus(ctx, r.Client, &host, status)
				if r.Recorder != nil {
					r.Recorder.Eventf(&host, nil, "Warning", "ImmutableFieldChanged", "Update", "%s", err.Error())
				}
				return ctrl.Result{}, err
			}
		}

		remoteID = existing.ID
		shouldSyncLabels := host.Spec.Labels != nil || host.Spec.GrantoryHostID == ""
		if shouldSyncLabels && !maps.Equal(existing.Labels, labels) {
			updated, err := r.GrantoryClient.UpdateHostLabels(ctx, host.Status.ID, labels)
			if err != nil {
				status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "UpdateFailed", err.Error(), host.Generation)
				_ = updateHostStatus(ctx, r.Client, &host, status)
				if r.Recorder != nil {
					r.Recorder.Eventf(&host, nil, "Warning", "UpdateFailed", "Update", "%s", err.Error())
				}
				return ctrl.Result{}, err
			}
			remoteID = updated.ID
		}
	}

	if remoteID == "" {
		return ctrl.Result{}, fmt.Errorf("grantory host ID missing after reconcile")
	}

	status.ID = remoteID
	status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionTrue, "Reconciled", "Host synced to Grantory", host.Generation)
	if err := updateHostStatus(ctx, r.Client, &host, status); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *GrantoryHostReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.GrantoryHost{}).
		Complete(r)
}
