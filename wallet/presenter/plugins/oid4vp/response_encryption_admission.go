package oid4vp

import "slices"

// validateResponseEncryptionMetadata refuses, while the request is parsed, a
// direct_post.jwt or dc_api.jwt request whose response this Wallet could not
// encrypt, with the selection the response will be encrypted with, so the
// refusal comes before consent. Under HAIP the Verifier must also list both
// A128GCM and A256GCM (HAIP §5).
func (b *requestCore) validateResponseEncryptionMetadata() error {
	if b.req.ResponseMode != OAuthAuthzReqResponseModeDirectPostJWT && b.req.ResponseMode != OAuthAuthzReqResponseModeDCAPIJWT {
		return nil
	}
	metadata := b.req.ClientMetadata
	if metadata == nil || len(metadata.Jwks.Keys) == 0 {
		return newAuthorizationRequestError(InvalidRequestError, "%w", ErrResponseEncryptionKeyMissing)
	}
	haip := b.haipRequestObjectPolicy()
	if _, err := selectResponseEncryptionForProfile(metadata, haip); err != nil {
		return newAuthorizationRequestError(InvalidRequestError, "%w", err)
	}
	if haip && (!slices.Contains(metadata.EncryptedResponseEncValuesSupported, "A128GCM") ||
		!slices.Contains(metadata.EncryptedResponseEncValuesSupported, "A256GCM")) {
		return newAuthorizationRequestError(InvalidRequestError, "%w", ErrResponseEncryptionEncMissing)
	}
	return nil
}
