package storage

import (
	"context"
	"time"
)

// SignatureParams encapsulates client signature verification details for bundled replay protection.
type SignatureParams struct {
	HostID    string
	Timestamp int64
	Nonce     string
	ExpiresAt time.Time
}

type signatureParamsKey struct{}

// WithSignatureParams returns a context carrying the specified SignatureParams.
func WithSignatureParams(ctx context.Context, p SignatureParams) context.Context {
	return context.WithValue(ctx, signatureParamsKey{}, p)
}

// SignatureParamsFromContext extracts SignatureParams from context if present.
func SignatureParamsFromContext(ctx context.Context) (SignatureParams, bool) {
	if ctx == nil {
		return SignatureParams{}, false
	}
	p, ok := ctx.Value(signatureParamsKey{}).(SignatureParams)
	return p, ok
}
