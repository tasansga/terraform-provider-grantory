package controller

import (
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const (
	grantoryFinalizer              = "grantory.ansgar.tasler.net/finalizer"
	ForceRemoveFinalizerAnnotation = "grantory.ansgar.tasler.net/force-remove-finalizer"
)

func hasForceRemoveAnnotation(obj client.Object) bool {
	annotations := obj.GetAnnotations()
	return annotations != nil && annotations[ForceRemoveFinalizerAnnotation] == "true"
}

func syncFinalizer(needed bool, obj client.Object) bool {
	has := controllerutil.ContainsFinalizer(obj, grantoryFinalizer)
	if needed && !has {
		controllerutil.AddFinalizer(obj, grantoryFinalizer)
		return true
	}
	if !needed && has {
		controllerutil.RemoveFinalizer(obj, grantoryFinalizer)
		return true
	}
	return false
}

func removeFinalizer(obj client.Object) bool {
	if !controllerutil.ContainsFinalizer(obj, grantoryFinalizer) {
		return false
	}
	controllerutil.RemoveFinalizer(obj, grantoryFinalizer)
	return true
}
