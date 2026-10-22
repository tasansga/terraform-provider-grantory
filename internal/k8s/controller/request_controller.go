package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	apiclient "github.com/tasansga/terraform-provider-grantory/api/client"
	"github.com/tasansga/terraform-provider-grantory/internal/k8s/api/v1alpha1"
)

const noGrantRequeueDelay = 10 * time.Second

type GrantoryRequestReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	Recorder            events.EventRecorder
	GrantoryClient      *apiclient.Client
	GrantoryNamespace   string
	DefaultHostProvider DefaultHostProvider
}

func (r *GrantoryRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var request v1alpha1.GrantoryRequest
	if err := r.Get(ctx, req.NamespacedName, &request); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if request.DeletionTimestamp != nil {
		if request.Spec.ShouldDeleteOnRemoval() && request.Status.ID != "" && !hasForceRemoveAnnotation(&request) {
			if r.DefaultHostProvider != nil && !r.DefaultHostProvider.IsReady() && request.Spec.HostID == "" && request.Spec.HostRef == nil && request.Spec.PrivateKeySecretRef == nil {
				return ctrl.Result{RequeueAfter: time.Second}, nil
			}
			var defaultHostID string
			if r.DefaultHostProvider != nil {
				if id, _ := r.DefaultHostProvider.GetDefaultHost(); id != "" {
					defaultHostID = id
				}
			}
			hostID, _, _ := resolveHostID(ctx, r.Client, request.Namespace, request.Spec.HostID, request.Spec.HostRef, defaultHostID)
			delCtx, err := resolveSigningContext(ctx, r.Client, request.Namespace, request.Spec.PrivateKeySecretRef, request.Spec.KeyFormat, hostID, request.Spec.HostRef, r.DefaultHostProvider)
			if err != nil && !apierrors.IsNotFound(err) {
				return ctrl.Result{}, err
			}
			secretMissing := err != nil && apierrors.IsNotFound(err)
			if err := r.GrantoryClient.DeleteRequest(delCtx, request.Status.ID); err != nil && !apiclient.IsNotFound(err) {
				if secretMissing && apiclient.IsUnauthorized(err) && r.Recorder != nil {
					r.Recorder.Eventf(&request, nil, "Warning", "SecretNotFoundCannotSignDelete", "Delete", "Signing secret missing; annotate with %s: 'true' to force finalizer removal", ForceRemoveFinalizerAnnotation)
				}
				return ctrl.Result{}, err
			}
		}
		if removeFinalizer(&request) {
			return ctrl.Result{}, r.Update(ctx, &request)
		}
		return ctrl.Result{}, nil
	}

	if syncFinalizer(request.Spec.ShouldDeleteOnRemoval(), &request) {
		return ctrl.Result{}, r.Update(ctx, &request)
	}

	var defaultHostID string
	if r.DefaultHostProvider != nil {
		if id, _ := r.DefaultHostProvider.GetDefaultHost(); id != "" {
			defaultHostID = id
		}
	}

	hostID, result, err := resolveHostID(ctx, r.Client, request.Namespace, request.Spec.HostID, request.Spec.HostRef, defaultHostID)
	if err != nil {
		if r.DefaultHostProvider != nil && request.Spec.HostID == "" && request.Spec.HostRef == nil {
			return ctrl.Result{RequeueAfter: time.Second}, nil
		}
		status := request.Status
		status.ObservedGeneration = request.Generation
		status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "InvalidHost", err.Error(), request.Generation)
		_ = updateRequestStatus(ctx, r.Client, &request, status)
		return ctrl.Result{}, err
	}
	if result.RequeueAfter > 0 {
		status := request.Status
		status.ObservedGeneration = request.Generation
		status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "WaitingForHost", "Waiting for referenced host", request.Generation)
		_ = updateRequestStatus(ctx, r.Client, &request, status)
		return result, nil
	}

	ctx, err = resolveSigningContext(ctx, r.Client, request.Namespace, request.Spec.PrivateKeySecretRef, request.Spec.KeyFormat, hostID, request.Spec.HostRef, r.DefaultHostProvider)
	if err != nil {
		if apierrors.IsNotFound(err) && request.Spec.PrivateKeySecretRef != nil {
			status := request.Status
			status.ObservedGeneration = request.Generation
			status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "WaitingForSecret", fmt.Sprintf("Waiting for referenced secret %s", request.Spec.PrivateKeySecretRef.Name), request.Generation)
			_ = updateRequestStatus(ctx, r.Client, &request, status)
			return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
		}
		status := request.Status
		status.ObservedGeneration = request.Generation
		status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "InvalidPrivateKey", err.Error(), request.Generation)
		_ = updateRequestStatus(ctx, r.Client, &request, status)
		return ctrl.Result{}, err
	}

	var response apiclient.Request
	desiredPayload, err := rawExtensionToMap(request.Spec.Payload)
	if err != nil {
		status := request.Status
		status.ObservedGeneration = request.Generation
		status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "InvalidPayload", err.Error(), request.Generation)
		_ = updateRequestStatus(ctx, r.Client, &request, status)
		return ctrl.Result{}, err
	}
	labels := request.Spec.Labels
	if labels == nil {
		labels = map[string]string{}
	}

	if request.Status.ID == "" {
		created, err := r.GrantoryClient.CreateRequest(ctx, apiclient.RequestCreatePayload{
			HostID:                    hostID,
			RequestSchemaDefinitionID: request.Spec.RequestSchemaDefinitionID,
			GrantSchemaDefinitionID:   request.Spec.GrantSchemaDefinitionID,
			UniqueKey:                 request.Spec.UniqueKey,
			Payload:                   desiredPayload,
			Mutable:                   request.Spec.Mutable,
			Labels:                    labels,
		})
		if err != nil {
			status := request.Status
			status.ObservedGeneration = request.Generation
			status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "CreateFailed", err.Error(), request.Generation)
			_ = updateRequestStatus(ctx, r.Client, &request, status)
			if r.Recorder != nil {
				r.Recorder.Eventf(&request, nil, "Warning", "CreateFailed", "Create", "%s", err.Error())
			}
			return ctrl.Result{}, err
		}
		response = created
		if r.Recorder != nil {
			r.Recorder.Eventf(&request, nil, "Normal", "Created", "Create", "Created Grantory request %s", created.ID)
		}
	} else {
		existing, err := r.GrantoryClient.GetRequest(ctx, request.Status.ID)
		if err != nil {
			if apiclient.IsNotFound(err) {
				status := request.Status
				status.ID = ""
				status.HasGrant = false
				status.GrantID = ""
				status.GrantPayload = runtime.RawExtension{}
				status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "NotFound", "Request not found in Grantory, will recreate", request.Generation)
				_ = updateRequestStatus(ctx, r.Client, &request, status)
				return ctrl.Result{}, nil
			}
			status := request.Status
			status.ObservedGeneration = request.Generation
			status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "GetFailed", err.Error(), request.Generation)
			_ = updateRequestStatus(ctx, r.Client, &request, status)
			return ctrl.Result{}, err
		}

		if existing.HostID != hostID {
			err := fmt.Errorf("request host identity is immutable on existing request (status=%s, current=%s, spec=%s); recreating is blocked to prevent signature invalidation", request.Status.ID, existing.HostID, hostID)
			status := request.Status
			status.ObservedGeneration = request.Generation
			status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "ImmutableFieldChanged", err.Error(), request.Generation)
			_ = updateRequestStatus(ctx, r.Client, &request, status)
			if r.Recorder != nil {
				r.Recorder.Eventf(&request, nil, "Warning", "ImmutableFieldChanged", "Update", "%s", err.Error())
			}
			return ctrl.Result{}, err
		}

		immutableFieldChanged := existing.RequestSchemaDefinitionID != request.Spec.RequestSchemaDefinitionID ||
			existing.GrantSchemaDefinitionID != request.Spec.GrantSchemaDefinitionID ||
			existing.UniqueKey != request.Spec.UniqueKey ||
			existing.Mutable != request.Spec.Mutable

		payloadChanged := !reflect.DeepEqual(normalizePayload(desiredPayload), normalizePayload(existing.Payload))
		labelsChanged := !maps.Equal(existing.Labels, labels)

		if immutableFieldChanged || (!request.Spec.Mutable && payloadChanged) {
			if err := r.GrantoryClient.DeleteRequest(ctx, existing.ID); err != nil && !apiclient.IsNotFound(err) {
				return ctrl.Result{}, err
			}
			status := request.Status
			status.ID = ""
			status.HasGrant = false
			status.GrantID = ""
			status.GrantPayload = runtime.RawExtension{}
			status.ObservedGeneration = request.Generation
			status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "SpecChanged", "Request immutable fields changed, recreating", request.Generation)
			_ = updateRequestStatus(ctx, r.Client, &request, status)
			return ctrl.Result{RequeueAfter: time.Second}, nil
		}

		response = existing
		if request.Spec.Mutable && (payloadChanged || labelsChanged) {
			updated, err := r.GrantoryClient.UpdateRequest(ctx, request.Status.ID, apiclient.RequestUpdatePayload{
				Payload: desiredPayload,
				Labels:  labels,
			})
			if err != nil {
				status := request.Status
				status.ObservedGeneration = request.Generation
				status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "UpdateFailed", err.Error(), request.Generation)
				_ = updateRequestStatus(ctx, r.Client, &request, status)
				if r.Recorder != nil {
					r.Recorder.Eventf(&request, nil, "Warning", "UpdateFailed", "Update", "%s", err.Error())
				}
				return ctrl.Result{}, err
			}
			response = updated
		} else if labelsChanged {
			updated, err := r.GrantoryClient.UpdateRequestLabels(ctx, request.Status.ID, labels)
			if err != nil {
				status := request.Status
				status.ObservedGeneration = request.Generation
				status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "UpdateFailed", err.Error(), request.Generation)
				_ = updateRequestStatus(ctx, r.Client, &request, status)
				if r.Recorder != nil {
					r.Recorder.Eventf(&request, nil, "Warning", "UpdateFailed", "Update", "%s", err.Error())
				}
				return ctrl.Result{}, err
			}
			response = updated
		}
	}

	status := request.Status
	status.ID = response.ID
	status.HasGrant = response.HasGrant
	status.GrantID = response.GrantID
	status.ObservedGeneration = request.Generation
	status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionTrue, "Reconciled", "Request synced to Grantory", request.Generation)
	var grantRaw []byte
	if response.Grant != nil {
		raw, err := grantPayloadRaw(response.Grant)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("marshal grant payload: %w", err)
		}
		grantRaw = raw
		if !strings.EqualFold(strings.TrimSpace(request.Spec.GrantOutputKind), "secret") {
			status.GrantPayload = runtime.RawExtension{Raw: raw}
		} else {
			status.GrantPayload = runtime.RawExtension{}
		}
	} else {
		status.GrantPayload = runtime.RawExtension{}
	}

	if err := updateRequestStatus(ctx, r.Client, &request, status); err != nil {
		return ctrl.Result{}, err
	}

	requeueResult := ctrl.Result{}
	if !response.HasGrant {
		requeueResult = ctrl.Result{RequeueAfter: noGrantRequeueDelay}
	}

	outputName := strings.TrimSpace(request.Spec.GrantOutputName)
	if outputName == "" {
		outputName = request.Name
	}

	if request.Spec.GrantOutputKind == "" {
		if err := r.cleanupGrantOutputs(ctx, request, ""); err != nil {
			return ctrl.Result{}, err
		}
		return requeueResult, nil
	}

	if err := r.cleanupGrantOutputs(ctx, request, outputName); err != nil {
		return ctrl.Result{}, err
	}

	if len(grantRaw) == 0 {
		if err := r.deleteGrantOutput(ctx, request, outputName); err != nil {
			return ctrl.Result{}, err
		}
		return requeueResult, nil
	}

	data, err := buildGrantOutputData(grantRaw, request.Spec.GrantOutputKeys)
	if err != nil {
		return ctrl.Result{}, err
	}

	switch strings.ToLower(strings.TrimSpace(request.Spec.GrantOutputKind)) {
	case "secret":
		var existing corev1.Secret
		if err := r.Get(ctx, types.NamespacedName{Name: outputName, Namespace: request.Namespace}, &existing); err == nil {
			if !isOwnedByRequest(&existing, &request) {
				err := fmt.Errorf("target output Secret %s/%s already exists and is not owned by this GrantoryRequest", request.Namespace, outputName)
				status := request.Status
				status.ObservedGeneration = request.Generation
				status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "OutputConflict", err.Error(), request.Generation)
				_ = updateRequestStatus(ctx, r.Client, &request, status)
				if r.Recorder != nil {
					r.Recorder.Eventf(&request, nil, "Warning", "OutputConflict", "Output", "%s", err.Error())
				}
				return ctrl.Result{}, err
			}
		} else if !apierrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      outputName,
				Namespace: request.Namespace,
			},
		}
		_, err := controllerutil.CreateOrUpdate(ctx, r.Client, secret, func() error {
			secret.Type = corev1.SecretTypeOpaque
			secret.Data = toSecretData(data)
			secret.StringData = nil
			return controllerutil.SetControllerReference(&request, secret, r.Scheme)
		})
		if err != nil {
			return ctrl.Result{}, err
		}
	case "configmap":
		var existing corev1.ConfigMap
		if err := r.Get(ctx, types.NamespacedName{Name: outputName, Namespace: request.Namespace}, &existing); err == nil {
			if !isOwnedByRequest(&existing, &request) {
				err := fmt.Errorf("target output ConfigMap %s/%s already exists and is not owned by this GrantoryRequest", request.Namespace, outputName)
				status := request.Status
				status.ObservedGeneration = request.Generation
				status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "OutputConflict", err.Error(), request.Generation)
				_ = updateRequestStatus(ctx, r.Client, &request, status)
				if r.Recorder != nil {
					r.Recorder.Eventf(&request, nil, "Warning", "OutputConflict", "Output", "%s", err.Error())
				}
				return ctrl.Result{}, err
			}
		} else if !apierrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
		configMap := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      outputName,
				Namespace: request.Namespace,
			},
		}
		_, err := controllerutil.CreateOrUpdate(ctx, r.Client, configMap, func() error {
			configMap.Data = data
			return controllerutil.SetControllerReference(&request, configMap, r.Scheme)
		})
		if err != nil {
			return ctrl.Result{}, err
		}
	default:
		return ctrl.Result{}, fmt.Errorf("unsupported grantOutputKind %q", request.Spec.GrantOutputKind)
	}

	return requeueResult, nil
}

func (r *GrantoryRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.GrantoryRequest{}).
		Owns(&corev1.Secret{}).
		Owns(&corev1.ConfigMap{}).
		Complete(r)
}

func grantPayloadRaw(grant map[string]any) ([]byte, error) {
	if grant == nil {
		return nil, nil
	}
	if payload, ok := grant["payload"]; ok {
		return json.Marshal(payload)
	}
	return json.Marshal(grant)
}

func (r *GrantoryRequestReconciler) deleteGrantOutput(ctx context.Context, request v1alpha1.GrantoryRequest, outputName string) error {
	switch strings.ToLower(strings.TrimSpace(request.Spec.GrantOutputKind)) {
	case "secret":
		var secret corev1.Secret
		if err := r.Get(ctx, types.NamespacedName{Name: outputName, Namespace: request.Namespace}, &secret); err != nil {
			if apierrors.IsNotFound(err) {
				return nil
			}
			return err
		}
		if isOwnedByRequest(&secret, &request) {
			if err := r.Delete(ctx, &secret); err != nil && !apierrors.IsNotFound(err) {
				return err
			}
		}
	case "configmap":
		var configMap corev1.ConfigMap
		if err := r.Get(ctx, types.NamespacedName{Name: outputName, Namespace: request.Namespace}, &configMap); err != nil {
			if apierrors.IsNotFound(err) {
				return nil
			}
			return err
		}
		if isOwnedByRequest(&configMap, &request) {
			if err := r.Delete(ctx, &configMap); err != nil && !apierrors.IsNotFound(err) {
				return err
			}
		}
	default:
		return fmt.Errorf("unsupported grantOutputKind %q", request.Spec.GrantOutputKind)
	}
	return nil
}

func (r *GrantoryRequestReconciler) cleanupGrantOutputs(ctx context.Context, request v1alpha1.GrantoryRequest, outputName string) error {
	desiredKind := strings.ToLower(strings.TrimSpace(request.Spec.GrantOutputKind))
	secretList := &corev1.SecretList{}
	if err := r.List(ctx, secretList, client.InNamespace(request.Namespace)); err != nil {
		return err
	}
	for i := range secretList.Items {
		secret := &secretList.Items[i]
		if !isOwnedByRequest(secret, &request) {
			continue
		}
		if desiredKind != "secret" || secret.Name != outputName {
			if err := r.Delete(ctx, secret); err != nil && !apierrors.IsNotFound(err) {
				return err
			}
		}
	}

	configMapList := &corev1.ConfigMapList{}
	if err := r.List(ctx, configMapList, client.InNamespace(request.Namespace)); err != nil {
		return err
	}
	for i := range configMapList.Items {
		configMap := &configMapList.Items[i]
		if !isOwnedByRequest(configMap, &request) {
			continue
		}
		if desiredKind != "configmap" || configMap.Name != outputName {
			if err := r.Delete(ctx, configMap); err != nil && !apierrors.IsNotFound(err) {
				return err
			}
		}
	}

	return nil
}

func isOwnedByRequest(obj metav1.Object, request *v1alpha1.GrantoryRequest) bool {
	if obj == nil || request == nil {
		return false
	}
	owner := metav1.GetControllerOf(obj)
	if owner == nil {
		return false
	}
	return owner.UID == request.UID
}

func buildGrantOutputData(raw []byte, mappings map[string]string) (map[string]string, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("grant payload is empty")
	}
	if len(mappings) == 0 {
		return map[string]string{
			"payload.json": string(raw),
		}, nil
	}

	var document interface{}
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, fmt.Errorf("parse grant payload: %w", err)
	}

	out := make(map[string]string, len(mappings))
	for pointer, key := range mappings {
		key = strings.TrimSpace(key)
		if key == "" {
			return nil, fmt.Errorf("grant output key cannot be empty for pointer %q", pointer)
		}
		value, err := resolveJSONPointer(document, pointer)
		if err != nil {
			return nil, err
		}
		stringValue, err := stringifyJSONValue(value)
		if err != nil {
			return nil, err
		}
		out[key] = stringValue
	}
	return out, nil
}

func resolveJSONPointer(document interface{}, pointer string) (interface{}, error) {
	if pointer == "" {
		return document, nil
	}
	if !strings.HasPrefix(pointer, "/") {
		return nil, fmt.Errorf("json pointer must start with '/': %q", pointer)
	}
	current := document
	for _, token := range strings.Split(pointer, "/")[1:] {
		token = strings.ReplaceAll(token, "~1", "/")
		token = strings.ReplaceAll(token, "~0", "~")
		switch typed := current.(type) {
		case map[string]interface{}:
			value, ok := typed[token]
			if !ok {
				return nil, fmt.Errorf("json pointer %q not found", pointer)
			}
			current = value
		case []interface{}:
			index, err := strconv.Atoi(token)
			if err != nil {
				return nil, fmt.Errorf("json pointer %q has non-numeric array index %q", pointer, token)
			}
			if index < 0 || index >= len(typed) {
				return nil, fmt.Errorf("json pointer %q array index %d out of range", pointer, index)
			}
			current = typed[index]
		default:
			return nil, fmt.Errorf("json pointer %q traversed non-container value", pointer)
		}
	}
	return current, nil
}

func stringifyJSONValue(value interface{}) (string, error) {
	if value == nil {
		return "", nil
	}
	switch typed := value.(type) {
	case string:
		return typed, nil
	case bool:
		if typed {
			return "true", nil
		}
		return "false", nil
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64), nil
	default:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return "", fmt.Errorf("encode json value: %w", err)
		}
		return string(encoded), nil
	}
}

func toSecretData(input map[string]string) map[string][]byte {
	if input == nil {
		return nil
	}
	out := make(map[string][]byte, len(input))
	for key, value := range input {
		out[key] = []byte(value)
	}
	return out
}
