package oid4vp

import (
	"slices"

	"github.com/trustknots/vcknots/wallet/profile"
)

// validateResponseEncryptionMetadata refuses, while the request is parsed, a
// direct_post.jwt or dc_api.jwt request whose response this Wallet could not
// encrypt, with the selection the response will be encrypted with, so the
// refusal comes before consent. Under ResponseEncryption.RequireVerifierGCMBoth
// the Verifier must also list both A128GCM and A256GCM (HAIP §5). A Draft 24
// request is held to the JARM selection of Draft 24 §8.3.
func (b *requestCore) validateResponseEncryptionMetadata() error {
	if b.req.ResponseMode != OAuthAuthzReqResponseModeDirectPostJWT && b.req.ResponseMode != OAuthAuthzReqResponseModeDCAPIJWT {
		return nil
	}
	metadata := b.req.ClientMetadata
	if metadata == nil || len(metadata.Jwks.Keys) == 0 {
		return newAuthorizationRequestError(InvalidRequestError, "%w", ErrResponseEncryptionKeyMissing)
	}
	if b.draft24JARM {
		if _, err := selectDraft24JARMEncryption(metadata); err != nil {
			return newAuthorizationRequestError(InvalidRequestError, "%w", err)
		}
		return nil
	}
	rules := b.options.ResponseEncryption
	if _, err := selectResponseEncryptionForProfile(metadata, rules); err != nil {
		return newAuthorizationRequestError(InvalidRequestError, "%w", err)
	}
	if rules.RequireVerifierGCMBoth && (!slices.Contains(metadata.EncryptedResponseEncValuesSupported, "A128GCM") ||
		!slices.Contains(metadata.EncryptedResponseEncValuesSupported, "A256GCM")) {
		return newAuthorizationRequestError(InvalidRequestError, "%w: %w", profile.Refused("ResponseEncryption.RequireVerifierGCMBoth"), ErrResponseEncryptionEncMissing)
	}
	return nil
}
