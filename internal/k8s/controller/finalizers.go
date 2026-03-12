package controller

import (
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const (
	grantoryFinalizer = "grantory.ansgar.tasler.net/finalizer"
)

func ensureFinalizer(needed bool, obj client.Object) bool {
	if !needed {
		return false
	}
	if controllerutil.ContainsFinalizer(obj, grantoryFinalizer) {
		return false
	}
	controllerutil.AddFinalizer(obj, grantoryFinalizer)
	return true
}

func removeFinalizer(obj client.Object) bool {
	if !controllerutil.ContainsFinalizer(obj, grantoryFinalizer) {
		return false
	}
	controllerutil.RemoveFinalizer(obj, grantoryFinalizer)
	return true
}
