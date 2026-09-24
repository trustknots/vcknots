package keystore

import "context"

// ContextSigner is an optional KeyEntry extension for keys whose signing
// operation can block, such as a hardware module or a remote signing service.
// When a key implements it, the library calls SignContext with the context of
// the operation the signature is for instead of Sign, so cancelling the
// operation also cancels a pending signature.
//
// SignContext returns a signature in the same encoding Sign does.
type ContextSigner interface {
	SignContext(ctx context.Context, data []byte) ([]byte, error)
}
