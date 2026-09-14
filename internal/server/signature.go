package server

import (
	"github.com/tasansga/terraform-provider-grantory/internal/storage"
)

type signatureBundler interface {
	SupportsSignatureBundling() bool
}

type storeUnwrapper interface {
	Unwrap() storage.Store
}

func checkSignatureBundling(s any) bool {
	if s == nil {
		return false
	}
	if sb, ok := s.(signatureBundler); ok && sb.SupportsSignatureBundling() {
		return true
	}
	if u, ok := s.(storeUnwrapper); ok {
		return checkSignatureBundling(u.Unwrap())
	}
	return false
}
