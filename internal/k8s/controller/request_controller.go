package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	apiclient "github.com/tasansga/terraform-provider-grantory/internal/api/client"
	"github.com/tasansga/terraform-provider-grantory/internal/k8s/api/v1alpha1"
)

const noGrantRequeueDelay = 10 * time.Second

type GrantoryRequestReconciler struct {
	client.Client
	Scheme            *runtime.Scheme
	Recorder          record.EventRecorder
	GrantoryClient    *apiclient.Client
	GrantoryNamespace string
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
		if request.Spec.DeleteOnRemoval && request.Status.ID != "" {
			if err := r.GrantoryClient.DeleteRequest(ctx, request.Status.ID); err != nil {
				if apiclient.IsNotFound(err) {
					// Already deleted.
				} else {
					return ctrl.Result{}, err
				}
			}
		}
		if removeFinalizer(&request) {
			return ctrl.Result{}, r.Update(ctx, &request)
		}
		return ctrl.Result{}, nil
	}

	if ensureFinalizer(request.Spec.DeleteOnRemoval, &request) {
		return ctrl.Result{}, r.Update(ctx, &request)
	}

	hostID, result, err := resolveHostID(ctx, r.Client, request.Namespace, request.Spec.HostID, request.Spec.HostRef)
	if err != nil {
		status := request.Status
		status.ObservedGeneration = request.Generation
		status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "InvalidHost", err.Error(), request.Generation)
		_ = updateRequestStatus(ctx, r.Client, &request, status)
		return ctrl.Result{}, err
	}
	if result.Requeue || result.RequeueAfter > 0 {
		status := request.Status
		status.ObservedGeneration = request.Generation
		status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "WaitingForHost", "Waiting for referenced host", request.Generation)
		_ = updateRequestStatus(ctx, r.Client, &request, status)
		return result, nil
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
	if request.Status.ID == "" {
		created, err := r.GrantoryClient.CreateRequest(ctx, apiclient.RequestCreatePayload{
			HostID:                    hostID,
			RequestSchemaDefinitionID: request.Spec.RequestSchemaDefinitionID,
			GrantSchemaDefinitionID:   request.Spec.GrantSchemaDefinitionID,
			UniqueKey:                 request.Spec.UniqueKey,
			Payload:                   desiredPayload,
			Labels:                    request.Spec.Labels,
		})
		if err != nil {
			status := request.Status
			status.ObservedGeneration = request.Generation
			status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "CreateFailed", err.Error(), request.Generation)
			_ = updateRequestStatus(ctx, r.Client, &request, status)
			if r.Recorder != nil {
				r.Recorder.Event(&request, "Warning", "CreateFailed", err.Error())
			}
			return ctrl.Result{}, err
		}
		response = created
		if r.Recorder != nil {
			r.Recorder.Eventf(&request, "Normal", "Created", "Created Grantory request %s", created.ID)
		}
	} else {
		labels := request.Spec.Labels
		if labels == nil {
			labels = map[string]string{}
		}
		updated, err := r.GrantoryClient.UpdateRequestLabels(ctx, request.Status.ID, labels)
		if err != nil {
			if apiclient.IsNotFound(err) {
				status := request.Status
				status.ID = ""
				status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "NotFound", "Request not found in Grantory, will recreate", request.Generation)
				_ = updateRequestStatus(ctx, r.Client, &request, status)
				return ctrl.Result{}, nil
			}
			status := request.Status
			status.ObservedGeneration = request.Generation
			status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "UpdateFailed", err.Error(), request.Generation)
			_ = updateRequestStatus(ctx, r.Client, &request, status)
			if r.Recorder != nil {
				r.Recorder.Event(&request, "Warning", "UpdateFailed", err.Error())
			}
			return ctrl.Result{}, err
		}
		response = updated
	}

	if !requestSpecMatchesResponse(request.Spec, hostID, desiredPayload, response) {
		if err := r.GrantoryClient.DeleteRequest(ctx, response.ID); err != nil && !apiclient.IsNotFound(err) {
			return ctrl.Result{}, err
		}
		status := request.Status
		status.ID = ""
		status.ObservedGeneration = request.Generation
		status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionFalse, "SpecChanged", "Request spec changed, recreating", request.Generation)
		_ = updateRequestStatus(ctx, r.Client, &request, status)
		return ctrl.Result{Requeue: true}, nil
	}

	status := request.Status
	status.ID = response.ID
	status.HasGrant = response.HasGrant
	status.GrantID = response.GrantID
	status.ObservedGeneration = request.Generation
	status.Conditions = setReadyCondition(status.Conditions, metav1.ConditionTrue, "Reconciled", "Request synced to Grantory", request.Generation)
	if response.Grant != nil {
		grantRaw, err := grantPayloadRaw(response.Grant)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("marshal grant payload: %w", err)
		}
		status.GrantPayload = runtime.RawExtension{Raw: grantRaw}
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
		if err := r.deleteAllGrantOutputs(ctx, request); err != nil {
			return ctrl.Result{}, err
		}
		return requeueResult, nil
	}

	if err := r.cleanupGrantOutputs(ctx, request, outputName); err != nil {
		return ctrl.Result{}, err
	}

	if len(status.GrantPayload.Raw) == 0 {
		if err := r.deleteGrantOutput(ctx, request, outputName); err != nil {
			return ctrl.Result{}, err
		}
		return requeueResult, nil
	}

	data, err := buildGrantOutputData(status.GrantPayload.Raw, request.Spec.GrantOutputKeys)
	if err != nil {
		return ctrl.Result{}, err
	}

	switch strings.ToLower(strings.TrimSpace(request.Spec.GrantOutputKind)) {
	case "secret":
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

func rawExtensionToMap(raw runtime.RawExtension) (map[string]any, error) {
	if len(raw.Raw) == 0 {
		return nil, nil
	}
	var out any
	if err := json.Unmarshal(raw.Raw, &out); err != nil {
		return nil, fmt.Errorf("parse payload: %w", err)
	}
	mapped, ok := out.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("payload must be a JSON object")
	}
	return mapped, nil
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

func requestSpecMatchesResponse(spec v1alpha1.GrantoryRequestSpec, hostID string, payload map[string]any, response apiclient.Request) bool {
	if response.HostID != hostID {
		return false
	}
	if response.RequestSchemaDefinitionID != spec.RequestSchemaDefinitionID {
		return false
	}
	if response.GrantSchemaDefinitionID != spec.GrantSchemaDefinitionID {
		return false
	}
	if response.UniqueKey != spec.UniqueKey {
		return false
	}
	return reflect.DeepEqual(normalizePayload(payload), normalizePayload(response.Payload))
}

func normalizePayload(payload map[string]any) map[string]any {
	if len(payload) == 0 {
		return nil
	}
	return payload
}

func (r *GrantoryRequestReconciler) deleteGrantOutput(ctx context.Context, request v1alpha1.GrantoryRequest, outputName string) error {
	switch strings.ToLower(strings.TrimSpace(request.Spec.GrantOutputKind)) {
	case "secret":
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      outputName,
				Namespace: request.Namespace,
			},
		}
		if err := r.Delete(ctx, secret); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	case "configmap":
		configMap := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      outputName,
				Namespace: request.Namespace,
			},
		}
		if err := r.Delete(ctx, configMap); err != nil && !apierrors.IsNotFound(err) {
			return err
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

func (r *GrantoryRequestReconciler) deleteAllGrantOutputs(ctx context.Context, request v1alpha1.GrantoryRequest) error {
	secretList := &corev1.SecretList{}
	if err := r.List(ctx, secretList, client.InNamespace(request.Namespace)); err != nil {
		return err
	}
	for i := range secretList.Items {
		secret := &secretList.Items[i]
		if !isOwnedByRequest(secret, &request) {
			continue
		}
		if err := r.Delete(ctx, secret); err != nil && !apierrors.IsNotFound(err) {
			return err
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
		if err := r.Delete(ctx, configMap); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	return nil
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
