package controller

import (
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	conditionReady = "Ready"
)

func setReadyCondition(conditions []metav1.Condition, status metav1.ConditionStatus, reason, message string, generation int64) []metav1.Condition {
	cond := metav1.Condition{
		Type:               conditionReady,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: generation,
		LastTransitionTime: metav1.Now(),
	}
	meta.SetStatusCondition(&conditions, cond)
	return conditions
}
