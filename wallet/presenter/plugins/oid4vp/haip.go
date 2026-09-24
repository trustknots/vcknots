package oid4vp

import (
	"fmt"
)

// enforceHAIPProfile applies the HAIP 1.0 constraints that can only be checked
// once the Authorization Request parameters have been assembled. It is inert
// for the Final profile.
func (b *requestBuilder) enforceHAIPProfile() error {
	// Record the observed delivery and whether the caller's
	// DeliveredByReference statement stood in for request_uri (HAIP §5.1).
	deliveryAttested := b.profile.IsHAIP() && b.requestSource == sourceValue && b.deliveredByReference
	if b.req.RequestObjectVerification != nil {
		b.req.RequestObjectVerification.Delivery = b.requestSource.delivery()
		b.req.RequestObjectVerification.DeliveryAttested = deliveryAttested
	}
	if !b.profile.IsHAIP() {
		return nil
	}
	// HAIP §5.2: "The Wallet MUST support the Response Mode dc_api.jwt" and
	// "The Wallet MUST support unsigned, signed, and multi-signed requests as
	// defined in Appendices A.3.1 and A.3.2". The request_uri encryption rule
	// of §5.1 is therefore relaxed for DC API modes.
	if b.requestSource.isDCAPI() {
		// HAIP §5.2: "The Verifier MUST use the Response Mode dc_api.jwt."
		// The unencrypted dc_api mode stays available to non-HAIP Final.
		if b.req.ResponseMode != OAuthAuthzReqResponseModeDCAPIJWT {
			return newAuthorizationRequestError(InvalidRequestError, "HAIP requires the response_mode dc_api.jwt for Digital Credentials API requests")
		}
		if b.requestSource == sourceDCAPIUnsigned {
			// An unsigned request has no Verifier client_id to authenticate.
			return nil
		}
		clientID, err := parseOID4VPClientID(b.req.ClientID)
		if err != nil {
			return err
		}
		if clientID.prefix != OID4VPClientIDPrefixX509Hash {
			// HAIP §5: "For signed requests, the Verifier MUST use, and the
			// Wallet MUST accept the Client Identifier Prefix x509_hash".
			return newAuthorizationRequestError(InvalidRequestError, "HAIP profile requires the x509_hash Client Identifier Prefix")
		}
		return nil
	}
	if b.requestSource != sourceReference && !deliveryAttested {
		// HAIP §5.1: "Signed Authorization Requests MUST be used by utilizing
		// JAR with the request_uri parameter".
		return fmt.Errorf("%w: %w",
			newAuthorizationRequestError(InvalidRequestError, "HAIP profile requires a signed Authorization Request delivered by request_uri"),
			ErrHAIPRequestURIRequired)
	}
	if b.req.ResponseMode != OAuthAuthzReqResponseModeDirectPostJWT {
		// HAIP §5.1: "Response encryption MUST be used by utilizing response
		// mode direct_post.jwt".
		return newAuthorizationRequestError(InvalidRequestError, "HAIP profile requires response_mode direct_post.jwt")
	}
	clientID, err := parseOID4VPClientID(b.req.ClientID)
	if err != nil {
		return err
	}
	if clientID.prefix != OID4VPClientIDPrefixX509Hash {
		// HAIP §5: "For signed requests, the Verifier MUST use, and the Wallet
		// MUST accept the Client Identifier Prefix x509_hash".
		return newAuthorizationRequestError(InvalidRequestError, "HAIP profile requires the x509_hash Client Identifier Prefix")
	}
	return nil
}
